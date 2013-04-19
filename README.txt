A very simple module to allow nagios service check results to be submitted via
NSCA.

Usage
=====

 >>> from pynsca import NSCANotifier
 >>> notif = NSCANotifier("nagios")
 >>> notif.svc_result("host", "service", pynsca.OK, "Looks Good!")

Requirements
============

* Python 2.4 or higher
* python-mcrypt, if using AES encryption
* pycrypto for 3DES 
* No other libraries required

Issues
======

Please file any bugs or feature requests at
  https://github.com/djmitche/pynsca/issues

Changes
=======

1.4
---

The library now supports 3DES encryption (mode 3).  This adds the requirement
for PyCrypto.
