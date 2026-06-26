"""Force a platform-specific (but Python-agnostic) wheel.

never_fox loads a prebuilt native library (libfxtls + vendored NSS) via ctypes —
there is no Python C-extension, so the wheel works on any CPython 3.x but is tied
to one OS+arch. We emit the `py3-none-<platform>` tag accordingly.
"""
from setuptools import setup

try:                                              # setuptools >= 70 vendors bdist_wheel
    from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:                               # older: comes from the wheel package
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


class bdist_wheel(_bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False                 # -> platform tag, not "any"

    def get_tag(self):
        _, _, plat = super().get_tag()
        return "py3", "none", plat                # any CPython 3.x, this platform


setup(cmdclass={"bdist_wheel": bdist_wheel})
