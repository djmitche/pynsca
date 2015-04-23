A very simple module to allow nagios service check results to be submitted via
NSCA.

Usage
=====

 >>> import pynsca
 >>> from pynsca import NSCANotifier
 >>> notif = NSCANotifier("nagios")
 >>> notif.svc_result("host", "service", pynsca.OK, "Looks Good!")
 
 Prebuild RPM packages
 =====================
 
 The Bareos project builds (using open build server) and publishes python-pynsca RPM packages for a 
 variety of RPM based Linux distribution, you can directly install from the repository:
 http://download.bareos.org/bareos/contrib/
 
 Debian / Ubuntu packages may follow later.

Requirements
============

* Python 2.4 or higher
* python-mcrypt, if using AES encryption
* pycrypto, if using 3DES encryption
* No other libraries required

Issues
======

Please file any bugs or feature requests at
  https://github.com/djmitche/pynsca/issues

Changes
=======

1.6 (Unreleased)
----------------

* Debian package updated.
* spec file to generate a RPM package.

1.5
---

PyCrypto is only required when using 3DES encryption (mode 3).

1.4
---

The library now supports 3DES encryption (mode 3).  This adds the requirement
for PyCrypto.
