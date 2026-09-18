"""Record the three demo GIFs against a running stack and write them to docs/assets/.

    cd backend && uv run python ../scripts/demo/make_gifs.py            # uses demo/state.json
    cd backend && uv run python ../scripts/demo/make_gifs.py --pr-url https://github.com/o/r/pull/1

Frames are captured by record.py in the web-capture image (headless Chromium); the
frontend must listen on 0.0.0.0 so the container can reach it through
host.docker.internal:
    __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=host.docker.internal npm run dev -- --host 0.0.0.0
"""

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "codeaudit-web-capture:1.63.0"


def record(scene: str, base: str, arg: str, width: int) -> Path:
    work = Path(tempfile.mkdtemp(prefix=f"gif-{scene}-"))
    work.chmod(0o777)
    shutil.copy(Path(__file__).with_name("record.py"), work / "record.py")
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{work}:/rec", "--add-host", "host.docker.internal:host-gateway",
         "--entrypoint", "python3", IMAGE, "/rec/record.py", scene, base, arg, "/rec/frames"],
        check=True,
    )
    frames = json.loads((work / "frames" / "frames.json").read_text())
    images, durations = [], []
    for name, ms in frames:
        image = Image.open(work / "frames" / name).convert("RGB")
        image = image.resize((width, round(image.height * width / image.width)), Image.LANCZOS)
        images.append(image.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
        durations.append(ms)
    target = ROOT / "docs" / "assets" / f"demo-{scene}.gif"
    target.parent.mkdir(parents=True, exist_ok=True)
    images[0].save(target, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True)
    shutil.rmtree(work, ignore_errors=True)
    print(f"{target.relative_to(ROOT)}: {len(images)} frames, {target.stat().st_size / 1e6:.1f} MB")
    return target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://host.docker.internal:5173")
    parser.add_argument("--scan-id", help="defaults to the demo scan in demo/state.json")
    parser.add_argument("--pr-url", help="defaults to pull_request_url in demo/state.json")
    parser.add_argument("--only", choices=["graph", "fixes", "pr"])
    parser.add_argument("--width", type=int, default=960)
    args = parser.parse_args()
    state = json.loads((ROOT / "demo" / "state.json").read_text()) if (ROOT / "demo" / "state.json").exists() else {}
    scan_id = args.scan_id or state["scans"]["demo"]["id"]
    pr_url = args.pr_url or state.get("pull_request_url")
    for scene in ("graph", "fixes", "pr"):
        if args.only and scene != args.only:
            continue
        if scene == "pr" and not pr_url:
            print("pr: skipped (no pull request URL)")
            continue
        record(scene, args.base, pr_url if scene == "pr" else scan_id, args.width)


if __name__ == "__main__":
    main()
