A very simple module to allow nagios service check results to be submitted via
NSCA.

== Usage ==
>>> from pynsca import NSCANotifier
>>> notif = NSCANotifier("nagios")
>>> notif.svc_result("host", "service", pynsca.OK, "Looks Good!")

== Requirements ==

 * Python 2.4 or higher
 * No other libraries required
