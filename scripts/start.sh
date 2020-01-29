ip link set ${IFACE} down
iw dev ${IFACE} set monitor control
ip link set ${IFACE}  up
iw dev ${IFACE} set channel ${DS_CHANNEL} 
cd /opt/dockersniff/
/usr/bin/python3 snift.py ${IFACE}
/bin/bash
