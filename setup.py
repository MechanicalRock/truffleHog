from setuptools import setup, find_packages
from time import time


setup(
    name="MechTruffleHog",
    version=f"1.0.0.dev{int(time())}",
    description="Searches through git repositories for high entropy strings and regex patterns. Suitable for local development and pipeline workflows.",
    url="https://github.com/MechanicalRock/truffleHog",
    author="Josh Crane",
    author_email="josh.crane@mechanicalrock.io",
    license="GNU",
    packages=["truffleHog"],
    install_requires=["GitPython", "jsons", "termcolor", "colorama"],
    package_data={"": ["*.json"]},
    include_package_data=True,
    entry_points={"console_scripts": ["mechtrufflehog = truffleHog.truffleHog:main"]},
)
