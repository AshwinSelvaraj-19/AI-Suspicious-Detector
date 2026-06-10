import os
import subprocess


def open_file_location(file_path):

    if not file_path:
        return False

    if not os.path.exists(file_path):
        return False

    subprocess.Popen(
        f'explorer /select,"{file_path}"'
    )

    return True