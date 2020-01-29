ip link set wlp2s0 down
iw dev wlp2s0 set monitor control
ip link set wlp2s0 up
iw dev wlp2s0 set channel ${DS_CHANNEL} 
cd /opt/dockersniff/
/usr/bin/python3 snift.py ${IFACE}
/bin/bash
