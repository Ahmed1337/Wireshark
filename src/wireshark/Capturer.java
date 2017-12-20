/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.pcap4j.packet.*;

/**
 *
 * @author Ahmed
 */
public class Capturer {

    private FXMLDocumentController controller;
    private List<PcapIf> alldevs;
    private StringBuilder errbuf;
    private Pcap pcap;
    private List detailedView;
    private List hexaView;
    private int number = 0;
    private double startTimeInSeconds;
    private boolean captureStart = false;

    protected Capturer(FXMLDocumentController controller) {
        this.controller = controller;
        detailedView = new ArrayList();
        hexaView = new ArrayList();
    }

    private double getCurrentTime() {
        return System.currentTimeMillis() / 1000.0;
    }

    private DnsPacket getDnsPacket(PcapPacket p) {
        Udp udp = new Udp();
        if (p.hasHeader(udp)) {
            try {
                return DnsPacket.newPacket(udp.getPayload(), 0, udp.getPayloadLength());
            } catch (Exception e) {
                return null;
            }
        } else {
            return null;
        }
    }

    protected List getDevices() {

        List devices = new ArrayList();
        alldevs = new ArrayList(); // Will be filled with NICs  
        errbuf = new StringBuilder(); // For any error msgs  
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.ERROR || alldevs.isEmpty()) {
            return null;
        }

        for (PcapIf device : alldevs) {
            String deviceName
                    = (device.getDescription() != null) ? device.getDescription()
                    : device.getName();
            devices.add(deviceName);
        }
        return devices;
    }

    protected void stopCapturing() {
        pcap.breakloop();
    }

    protected String getHex(int packetNum) {
        return (String) hexaView.get(packetNum);
    }

    protected String getDetailedData(int packetNum) {
        return ((StringBuilder) detailedView.get(packetNum)).toString();
    }

    protected String getInfo(int packetNum, String protocol) {
        try {
            String info = "";
            String data = getDetailedData(packetNum);
            char opCode;
            int index = 0;
            switch (protocol) {
                case "UDP":
                    index = data.indexOf("Udp");
                    index = data.indexOf("source = ", index);
                    info += data.substring(index + "source = ".length(), index = data.indexOf("\n", index));
                    index = data.indexOf("destination = ", index);
                    info += " → " + data.substring(index + "destination = ".length(), index = data.indexOf("\n", index));
                    index = data.indexOf("length =", index);
                    info += " Len=" + data.substring(index + "length =".length(), index = data.indexOf("\n", index));
                    break;
                case "TCP":
                    //can be global
                    String[] flags = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR"};
                    index = data.indexOf("Tcp");
                    index = data.indexOf("source = ", index);
                    info += data.substring(index + "source = ".length(), index = data.indexOf("\n", index));
                    index = data.indexOf("destination = ", index);
                    info += " → " + data.substring(index + "destination = ".length(), index = data.indexOf("\n", index));

                    //seq,ack
                    index = data.indexOf("seq = ", index);
                    index = data.indexOf("(", index);
                    String seq = " Seq=" + data.substring(index + 1, index = data.indexOf(")\n", index));
                    index = data.indexOf("ack = ", index);
                    index = data.indexOf("(", index);
                    String ack = " Ack=" + data.substring(index + 1, index = data.indexOf(")\n", index));
                    index = data.indexOf("flags = ", index);
                    int flag = Integer.parseInt(data.substring(data.indexOf("(", index) + 1, index = data.indexOf(")", index)));
                    info += " [";
                    for (int i = 0; i < flags.length; i++) {
                        if ((flag & (1 << i)) > 0) {
                            info += flags[i] + ",";
                        }
                    }
                    info += "]";
                    info = info.replaceAll(",]", "] ");
                    index = data.indexOf("window = ", index);
                    info += seq + ack;
                    info += " Win=" + data.substring(index + "window = ".length(), index = data.indexOf("\n", index));
                    break;
                case "HTTP":
                    if ((index = data.indexOf("Http:")) > -1) {
                        for (int i = 0; i < 3; i++) {
                            index = data.indexOf(" = ", index);
                            info += data.substring(index + " = ".length(), index = data.indexOf("\n", index + 1)) + " ";
                        }
                        if ((index = data.indexOf("CONTENT-TYPE = ")) > -1) {
                            int finalIndex = data.indexOf(";", index);
                            if (finalIndex > -1) {
                                finalIndex = Math.min(finalIndex, data.indexOf("\n", index));
                            } else {
                                finalIndex = data.indexOf("\n", index);
                            }
                            info += "(" + data.substring(index + "CONTENT-TYPE = ".length(), index = finalIndex) + ")";
                        }
                    } else {   //to be verified
                        index = data.indexOf("\n\nHttp packet is assembled from the following tcp packets\n\nTCP packet #") + "\n\nHttp packet is assembled from the following tcp packets\n\nTCP packet #".length();
                        int TCPsegment = Integer.parseInt(data.substring(index, data.indexOf("\n", index))) - 1;
                        data = getDetailedData(TCPsegment).toString();
                        index = data.indexOf("Http:");
                        for (int i = 0; i < 3; i++) {
                            index = data.indexOf(" = ", index);
                            info += data.substring(index + " = ".length(), index = data.indexOf("\n", index + 1)) + " ";
                        }
                        if ((index = data.indexOf("CONTENT-TYPE = ")) > -1) {
                            int finalIndex = data.indexOf(";", index);
                            if (finalIndex > -1) {
                                finalIndex = Math.min(finalIndex, data.indexOf("\n", index));
                            } else {
                                finalIndex = data.indexOf("\n", index);
                            }
                            info += "(" + data.substring(index + "CONTENT-TYPE = ".length(), index = finalIndex) + ")";
                        }
                    }
                    break;
                case "ICMP":
                    index = data.indexOf("ttl = ");
                    String ttl = data.substring(index + "ttl = ".length(), index = data.indexOf(" [", index));
                    index = data.indexOf("Icmp", index);
                    index = data.indexOf("[", index);
                    info += data.substring(index + 1, index = data.indexOf("]\n", index)) + "  ";
                    index = data.indexOf("id = ");
                    index = data.indexOf("(", index);
                    info += "id=" + data.substring(index + 1, index = data.indexOf(")\n", index)) + " ";
                    index = data.indexOf("sequence = ");
                    index = data.indexOf("(", index);
                    info += "seq=" + data.substring(index + 1, index = data.indexOf(")\n", index)) + " ttl=" + ttl;
                    break;
                case "ARP":
                    index = data.indexOf("Arp");
                    index = data.indexOf("op code = ", index);
                    opCode = data.charAt(index + "op code = ".length());
                    index = data.indexOf("sender MAC = ", index);
                    String sendMac = data.substring(index + "sender MAC = ".length(), index = data.indexOf("\n", index));
                    index = data.indexOf("sender IP = ", index);
                    String sendIP = data.substring(index + "sender IP = ".length(), index = data.indexOf("\n", index));
                    index = data.indexOf("target MAC = ", index);
                    String targetMac = data.substring(index + "target MAC = ".length(), index = data.indexOf("\n", index));
                    index = data.indexOf("target IP = ", index);
                    String targetIP = data.substring(index + "target IP = ".length(), index = data.indexOf("\n", index));
                    if (opCode == '1') {
                        if (targetMac.equals("00:00:00:00:00:00")) {
                            info = "Who has " + targetIP + "? Tell " + sendIP;
                        } else if (targetMac.equals("ff:ff:ff:ff:ff:ff")) {
                            info = "Gratuitous ARP for " + sendIP + " (request)";
                        }
                    } else if (opCode == '2') {
                        info = sendIP + " is at " + sendMac;
                    }
                    break;
                case "DNS":
                    index = data.indexOf("DNS Header");
                    index = data.indexOf("ID: ", index);
                    String id = ", ID: " + data.substring(index + "ID: ".length(), index = data.indexOf("\n", index) - 1);
                    index = data.indexOf("QR: ", index);
                    String type = data.substring(index + "QR: ".length(), index = data.indexOf("\n", index) - 1);
                    index = data.indexOf("OPCODE: ", index);
                    opCode = data.charAt(index + "OPCODE: ".length());
                    if (opCode == '0') {
                        info = "Standard query";
                        if (type.equals("response")) {
                            info += " response";
                        }
                        info += id;
                    }
                    index = data.indexOf("QTYPE: ",index);
                    index = data.indexOf("(",index);
                    info +=", Type: "+data.substring(index+1,index = data.indexOf("(",index+1));
                    break;
            }
            return info;
        } catch (Exception ex) {
            return "";
        }
    }

    protected void startCapturing(int deviceNum) {

        PcapIf device = alldevs.get(deviceNum);
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 60 * 1000;           // 60 seconds in millis  
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            private Ethernet eth = new Ethernet();
            private Http http = new Http();
            private Tcp tcp = new Tcp();
            private Ip4 ip = new Ip4();
            private Arp arp = new Arp();
            private Udp udp = new Udp();
            private Icmp icmp = new Icmp();
            private DnsPacket dns;
            private boolean packetCaptured = false;
            private List row;

            @Override
            public void nextPacket(PcapPacket packet, String user) {
                try {
                    if (!packetCaptured) {
                        pcap.setTimeout(Pcap.DEFAULT_TIMEOUT);
                        packetCaptured = true;
                    }
                    String protocol = null;
                    row = new ArrayList();
                    dns = getDnsPacket(packet);
                    if (packet.hasHeader(eth) && (packet.hasHeader(arp) || (packet.hasHeader(ip) && (packet.hasHeader(icmp) || packet.hasHeader(tcp) || packet.hasHeader(udp))))) {
                        detailedView.add(new StringBuilder(packet.toString()));
                        hexaView.add(packet.toHexdump());
                        row.add(number++ + 1);
                        row.add(((int) ((getCurrentTime() - startTimeInSeconds) * 10000)) / 10000.0);

                        if (packet.hasHeader(arp) && packet.hasHeader(eth)) {
                            row.add(FormatUtils.mac(eth.source()));
                            row.add(FormatUtils.mac(eth.destination()));
                            protocol = "ARP";
                        } else if (packet.hasHeader(ip)) {
                            row.add(FormatUtils.ip(ip.source()));
                            row.add(FormatUtils.ip(ip.destination()));
                            if (packet.hasHeader(udp)) {
                                protocol = "UDP";
                                if (dns != null) {
                                    protocol = "DNS";
                                    StringBuilder detailedData = (StringBuilder) detailedView.get(detailedView.size() - 1);
                                    detailedData.append("DNS-information" + dns.toString());
                                }
                            } else if (packet.hasHeader(tcp)) {
                                protocol = "TCP";
                                if (packet.hasHeader(http)) {
                                    if (!http.isResponse()) {
                                        protocol = "HTTP";
                                    } else {
                                        int contentLength = Integer.parseInt((http.fieldValue(Http.Response.Content_Length) != null) ? http.fieldValue(Http.Response.Content_Length) : "5555555");
                                        if (http.getPayload().length < contentLength) {
                                            HttpHandler.initiateHttpPacket(number, tcp.seq(), tcp.getPayloadLength(), contentLength, http.getPayload());
                                        } else {
                                            protocol = "HTTP";
                                        }
                                    }
                                }
                                String str = HttpHandler.handleForHttpIfExpected(tcp.seq(), tcp.getPayloadLength(), number, tcp.getPayload());
                                if (str != null) {
                                    protocol = "HTTP";
                                    StringBuilder detailedData = (StringBuilder) detailedView.get(detailedView.size() - 1);
                                    detailedData.append("HTTP-reassembly" + str);
                                    //System.out.println(str);
                                }
                            } else if (packet.hasHeader(icmp)) {
                                protocol = "ICMP";
                            }
                        }

                        row.add(protocol);
                        row.add(packet.getTotalSize());
                        row.add(getInfo(number - 1, protocol));
                        controller.addtoTable(row);
                        System.out.println(detailedView.get(detailedView.size() - 1).toString());

                    }

                    // JFormatterTextFormatter;
                    //System.out.println(detailedData);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }

            }
        };

        startTimeInSeconds = getCurrentTime();
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");

    }

}
