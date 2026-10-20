#!/usr/bin/env python3
"""Execute trusted JDK tools without ambient agents/classpath.
The caller constructs the argument vector; uploaded build scripts are not invoked.
"""
import os,sys
if len(sys.argv)<2 or sys.argv[1] not in ('java','javac'):
 raise SystemExit('JAVA_CLEAN_EXPECTS_JAVA_OR_JAVAC')
env=dict(os.environ)
for key in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):
 env.pop(key,None)
os.execvpe(sys.argv[1],sys.argv[1:],env)
