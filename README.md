python-snmpbulkwalk
===================

Simple pure-python implementation of SNMP v2 call snmpbulkwalk


Typical usage:
```
from snmpbulkwalk import snmpbulkwalk
res = snmpbulkwalk(host, oid, community)

# the res will be dict with oid as key and value as value
# for integer, counter, gauge & timetick response types 
#                           value will be type of integer
# for string and oid response types value will be string
# ipaddr type value returned as string like '127.0.0.1'

# unprintable string value returns as-is 
# (as nonprintable, NO HEX convertions is done)
# for example mac address value will be returned as 6 bytes string !
```

This method created primary for internal usage to get data from 1000+ devices every minute
IT IS not full support of SNMP protocol, it just simple create request packet and make simple unparse of response packet
without full support of all answer messsages, no error handling, no full validation of response.

Author: Ivan Zhiltsov (ivan.zhiltsov@pyzzle.ru)
Created to be used inside www.pyzzle.ru ISP management system

