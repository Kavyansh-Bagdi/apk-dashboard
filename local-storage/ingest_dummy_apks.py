
import hashlib
import json
import os
from pathlib import Path

from minio import Minio
from minio.error import S3Error


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


FILENAMES = [
    "0000A6D452D58424A8B7613F175AF5937F590033616B808BF8C0445695F82541",
    "000000000000000000000000000000000000000000000000000000000000000A",
    "0000000000000000000000000000000000000000000000000000000000000009",
    "0000000000000000000000000000000000000000000000000000000000000008",
    "0000000000000000000000000000000000000000000000000000000000000007",
    "0000000000000000000000000000000000000000000000000000000000000006",
    "0000000000000000000000000000000000000000000000000000000000000005",
    "0000000000000000000000000000000000000000000000000000000000000004",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000001",
]


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    config = load_config()

    client = Minio(
        endpoint=config["endpoint"],
        access_key=config["access_key"],
        secret_key=config["secret_key"],
        secure=config.get("secure", False),
    )

    bucket = config.get("bucket", "vulnerable-apks")
    file_size = max(256, int(config.get("file_size_bytes", 2048)))

    output_dir = BASE_DIR / config.get(
        "output_dir", "generated-apks"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create the bucket if it does not exist.
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
        print(f"Created bucket: {bucket}")
    else:
        print(f"Using existing bucket: {bucket}")

    uploaded = 0

    for name in FILENAMES:
        filename = f"{name}.apk"
        file_path = output_dir / filename

        # Generate harmless placeholder bytes.
        # These files are not valid or executable APKs.
        header = f"DUMMY_APK_TEST_FILE_{name}\n".encode("utf-8")
        content = (header + os.urandom(file_size))[:file_size]

        # Pad to the requested size if needed.
        if len(content) < file_size:
            content += os.urandom(file_size - len(content))

        with file_path.open("wb") as file:
            file.write(content)

        sha256 = hashlib.sha256(content).hexdigest()

        try:
            result = client.fput_object(
                bucket_name=bucket,
                object_name=filename,
                file_path=str(file_path),
                content_type="application/octet-stream",
            )

            uploaded += 1

            print(f"Uploaded: {result.object_name}")
            print(f"  Size:   {len(content)} bytes")
            print(f"  SHA256: {sha256}")

        except S3Error as error:
            print(f"Failed to upload {filename}: {error}")
            raise

    print(
        f"\nSuccessfully uploaded {uploaded} dummy files "
        f"to bucket '{bucket}'."
    )


if __name__ == "__main__":
    main()
