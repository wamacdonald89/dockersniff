FROM ubuntu:19.10 
RUN apt-get update
RUN apt-get install -y bash docker iw iproute2 python3-dev pyrit python3-pip aircrack-ng vim libpcap0.8 libpcap-dev 
RUN pip3 install PyRIC netaddr scapy PrettyTable
RUN mkdir /opt/dockersniff/
ADD scripts/start.sh /opt/dockersniff/start.sh
ADD scripts/snift.py /opt/dockersniff/snift.py
ADD scripts/packet.py /opt/dockersniff/packet.py
ADD pyrit/pyrit.db /opt/dockersniff/pyrit.db
RUN chmod +x /opt/dockersniff/start.sh
ENTRYPOINT [ "/bin/bash", "/opt/dockersniff/start.sh"]
CMD []
