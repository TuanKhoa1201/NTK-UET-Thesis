"""Sequential local JSON-lines model client. Reuses the byte-pinned B33 worker."""
from __future__ import annotations
import os
from pathlib import Path
import select
import signal
import subprocess
import time
from ntk_core import Blocker, canonical, loads, require


def offline_env():
    env = dict(os.environ)
    for key in ('PYTHONPATH', 'PYTHONHOME'):
        env.pop(key, None)
    env.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1',
               TOKENIZERS_PARALLELISM='false', PYTHONDONTWRITEBYTECODE='1',
               WANDB_DISABLED='true', DO_NOT_TRACK='1', GIT_OPTIONAL_LOCKS='0')
    return env


class Worker:
    """Bounded pipe reads: a partial/non-newline reply must not hang past timeout."""
    def __init__(self, argv, stderr_path, cwd, env=None):
        self.stderr = Path(stderr_path).open('xb')
        self.process = subprocess.Popen(list(map(str, argv)), cwd=cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            bufsize=0, close_fds=True, start_new_session=True, env=env or offline_env())
        self.buffer = b''
        self.cleanup = None

    def read(self, timeout):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            left = deadline - time.monotonic()
            require(left > 0, 'WORKER_TIMEOUT')
            ready, _, _ = select.select([self.process.stdout], [], [], left)
            require(bool(ready), 'WORKER_TIMEOUT')
            part = os.read(self.process.stdout.fileno(), 65536)
            require(bool(part), 'WORKER_EXITED_BEFORE_COMPLETE_REPLY')
            self.buffer += part
            require(len(self.buffer) <= 4 * 1024**2, 'WORKER_REPLY_TOO_LARGE')
        line, self.buffer = self.buffer.split(b'\n', 1)
        reply = loads(line)
        require(isinstance(reply, dict), 'WORKER_REPLY_NOT_OBJECT')
        return reply

    def request(self, messages, timeout):
        require(len(messages) == 2 and [m.get('role') for m in messages] == ['system', 'user'],
                'TARGET_OR_UNEXPECTED_MESSAGE_IN_MODEL_REQUEST')
        payload = (canonical({'messages': messages}) + '\n').encode()
        require(len(payload) <= 512 * 1024, 'WORKER_REQUEST_TOO_LARGE')
        # A single outstanding request. Handle partial writes explicitly.
        fd = self.process.stdin.fileno()
        offset, deadline = 0, time.monotonic() + timeout
        os.set_blocking(fd, False)
        try:
            while offset < len(payload):
                left = deadline - time.monotonic()
                require(left > 0, 'WORKER_WRITE_TIMEOUT')
                _, ready, _ = select.select([], [fd], [], left)
                require(bool(ready), 'WORKER_WRITE_TIMEOUT')
                try:
                    offset += os.write(fd, payload[offset:])
                except BlockingIOError:
                    pass
        except BrokenPipeError:
            raise Blocker('WORKER_BROKEN_PIPE') from None
        finally:
            os.set_blocking(fd, True)
        return self.read(max(0.001, deadline - time.monotonic()))

    def close(self):
        if self.cleanup is not None:
            return self.cleanup
        escalations = []
        try:
            if self.process.stdin:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                    if self.process.poll() is not None:
                        break
                    escalations.append(sig.name)
                    try:
                        os.killpg(self.process.pid, sig)
                    except ProcessLookupError:
                        pass
                    try:
                        self.process.wait(timeout=grace)
                    except subprocess.TimeoutExpired:
                        continue
        finally:
            if self.process.stdout:
                self.process.stdout.close()
            self.stderr.close()
        self.cleanup = {'pid': self.process.pid, 'returncode': self.process.poll(),
                        'escalations': escalations, 'own_process_only': True,
                        'still_running': self.process.poll() is None}
        return self.cleanup
