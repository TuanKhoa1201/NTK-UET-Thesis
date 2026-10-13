#!/usr/bin/env bash
# ==============================================================================
# Script Khởi chạy Tự động 1-Lệnh (One-Click Demo Runner)
# Đồ án Tốt nghiệp: Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp
#                   phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn.
# Tác giả: Nguyễn Tuấn Khoa | UET
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_EXEC="/home/tuankhoa/miniconda3/envs/iris/bin/python"

if [ ! -f "$PYTHON_EXEC" ]; then
    PYTHON_EXEC="$(which python3)"
fi

echo "======================================================================"
echo "    KHỞI CHẠY DEMO HỆ THỐNG HYBRID SAST + LOCAL LLM (NTK/IRIS)"
echo "======================================================================"

exec "$PYTHON_EXEC" "$SCRIPT_DIR/run_operation_pipeline.py" "$@"
