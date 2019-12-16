from setuptools import setup, find_packages

setup(
    name="MechTruffleHog",
    version="1",
    description="Searches through git repositories for high entropy strings and regex patterns. Suitable for local development and pipeline workflows.",
    url="https://github.com/MechanicalRock/truffleHog",
    author="Josh Crane",
    author_email="josh.crane@mechanicalrock.io",
    license="GNU",
    packages=["truffleHog"],
    install_requires=["GitPython", "jsons", "termcolor"],
    entry_points={"console_scripts": ["trufflehog = truffleHog.truffleHog:main"]},
)
