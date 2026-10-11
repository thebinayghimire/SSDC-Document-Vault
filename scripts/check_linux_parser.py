"""Exercise the production parser restrictions with synthetic Linux files only."""

import json
import subprocess
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    setup = "from pathlib import Path; from PIL import Image; import runpy,socket; Image.new('RGB',(80,60),'green').save('/tmp/selected.png'); Path('/tmp/unrelated').write_text('synthetic'); "
    restrictions = "policy=runpy.run_path('/fixture-code/parser_sandbox.py'); policy['restrict_parser'](Path('/tmp/selected.png')); assert Path('/tmp/selected.png').read_bytes(); denied=0\nfor action in (lambda: Path('/tmp/unrelated').read_bytes(),lambda: Path('/run/secrets/unrelated').read_bytes(),lambda: Path('/tmp/selected.png').write_bytes(b'tampered'),lambda: socket.socket(),lambda: Path('/proc/self/fd').iterdir().__next__()):\n try: action()\n except (PermissionError,FileNotFoundError): denied+=1\nassert denied == 5, denied\nprint('Parser restrictions: unrelated files/secrets, input writes, sockets and process descriptors denied')"
    common = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--network",
        "none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-v",
        str(root / "vault") + ":/fixture-code:ro",
        "ssdc-vault-app",
    ]
    result = subprocess.run(
        common + ["python", "-c", setup + restrictions], check=True, capture_output=True, text=True
    )
    print(result.stdout.strip())
    options = json.dumps({"pixels": 20000000, "pages": 500, "thumbnail": True, "sandbox": True})
    code = (
        setup
        + "import sys; sys.argv=['/fixture-code/validation.py','/tmp/selected.png','selected.png',"
        + repr(options)
        + "]; runpy.run_path('/fixture-code/validation.py',run_name='__main__')"
    )
    result = subprocess.run(
        common + ["python", "-c", code], check=True, capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    assert data.get("mime") == "image/png" and data.get("thumbnail"), data
    print("Production sandbox inspection and thumbnail generation passed.")


if __name__ == "__main__":
    main()
