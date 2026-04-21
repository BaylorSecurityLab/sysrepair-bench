"""Minimal SNMPv2c agent with the deliberately-vulnerable 'public' community.

Stands in for Windows' deprecated SNMP service, which is no longer shipped in the
ltsc2019 Server Core container image (the Windows capability has been removed
from the base image's component store). The scenario shape is preserved:

  * UDP/161 open to the world
  * Community string 'public' grants both READ and WRITE access
  * A couple of OIDs under 1.3.6.1.2.1.1 (sysDescr / sysName) return data
  * Authentication traps are effectively disabled (we never emit any)

The agent is exploitable with snmp-check / snmpwalk / snmpset using 'public'.
"""
import os
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.smi import builder
from pysnmp.proto.api import v2c


def main():
    snmp_engine = engine.SnmpEngine()

    config.addTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 161)),
    )

    # SNMPv2c with community 'public' — READ-WRITE (permits set-request).
    config.addV1System(snmp_engine, 'rw-area', 'public')
    config.addVacmUser(
        snmp_engine, 2, 'rw-area', 'noAuthNoPriv',
        readSubTree=(1, 3, 6),
        writeSubTree=(1, 3, 6),
    )

    snmp_context = context.SnmpContext(snmp_engine)

    mib_builder = snmp_context.getMibInstrum().getMibBuilder()
    MibScalar, MibScalarInstance = mib_builder.importSymbols(
        'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance',
    )

    class SysDescr(MibScalarInstance):
        def getValue(self, name, idx):
            return self.getSyntax().clone(
                'Meta3 SNMP Agent (sysrepair-bench scenario-01-snmp)'
            )

    class SysName(MibScalarInstance):
        def getValue(self, name, idx):
            return self.getSyntax().clone(os.environ.get('COMPUTERNAME', 'meta3-win-01'))

    mib_builder.exportSymbols(
        '__META3_SNMP',
        MibScalar((1, 3, 6, 1, 2, 1, 1, 1), v2c.OctetString()),
        SysDescr((1, 3, 6, 1, 2, 1, 1, 1), (0,), v2c.OctetString()),
        MibScalar((1, 3, 6, 1, 2, 1, 1, 5), v2c.OctetString()),
        SysName((1, 3, 6, 1, 2, 1, 1, 5), (0,), v2c.OctetString()),
    )

    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
    cmdrsp.SetCommandResponder(snmp_engine, snmp_context)

    snmp_engine.transportDispatcher.jobStarted(1)
    try:
        snmp_engine.transportDispatcher.runDispatcher()
    except Exception:
        snmp_engine.transportDispatcher.closeDispatcher()
        raise


if __name__ == '__main__':
    main()
