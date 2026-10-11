"""Prove snapshot exclusion and crash release without touching service volumes."""

import subprocess


def main():
    code = r"""import os, subprocess, sys
os.environ['PRIVATE_STORAGE_ROOT']='/tmp/synthetic'
os.environ['DJANGO_SETTINGS_MODULE']='config.settings'
from vault.maintenance import maintenance_lock
child = 'from vault.maintenance import maintenance_lock,MaintenanceBusy; import sys;\ntry:\n with maintenance_lock(exclusive=sys.argv[1]=="exclusive"): pass\nexcept MaintenanceBusy: sys.exit(42)'
def check(mode, expected):
 result=subprocess.run([sys.executable,'-c',child,mode])
 assert result.returncode == expected, (mode,result.returncode)
with maintenance_lock():
 check('shared',0)
 check('exclusive',42)
with maintenance_lock(exclusive=True):
 check('shared',42)
 check('exclusive',42)
check('shared',0)
crash='from vault.maintenance import maintenance_lock; import os;\nwith maintenance_lock(exclusive=True): os._exit(1)'
subprocess.run([sys.executable,'-c',crash])
check('exclusive',0)
print('Linux maintenance checks passed: request/job exclusion, duplicate snapshot denial, lock release on crash')
"""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "ssdc-vault-candidate-app",
            "python",
            "-c",
            code,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
