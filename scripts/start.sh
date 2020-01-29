ip link set ${IFACE} down
iw dev wlp2s0 set monitor control
ip link set ${IFACE}  up
iw dev wlp2s0 set channel ${DS_CHANNEL} 
cd /opt/dockersniff/
/usr/bin/python3 snift.py ${IFACE}
/bin/bash
