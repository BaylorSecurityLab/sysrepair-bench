"""Functional probe used by verify.ps1.

Exit codes:
  0 — GET with 'public' succeeded (scenario still vulnerable)
  2 — GET with 'public' returned no data / was rejected (remediated)
  3 — UDP/161 unreachable (regression)
"""
import sys
from pysnmp.hlapi import (
    CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
    UdpTransportTarget, getCmd,
)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('public', mpModel=1),
        UdpTransportTarget((host, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication is not None:
        # Timeout or socket failure = service down
        print(f'REGRESSION: {errorIndication}')
        sys.exit(3)
    if errorStatus:
        print(f'REMEDIATED: errorStatus={errorStatus.prettyPrint()}')
        sys.exit(2)
    for varBind in varBinds:
        print(' = '.join(x.prettyPrint() for x in varBind))
    sys.exit(0)


if __name__ == '__main__':
    main()
