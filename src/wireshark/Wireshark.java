/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import org.jnetpcap.packet.format.FormatUtils;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;

/**
 *
 * @author Ahmed
 */
public class Wireshark extends Application {

    public static final String Number = "Number";
    public static final String Time = "Time";
    public static final String Source = "Source";
    public static final String Destination = "Destination";
    public static final String Protocol = "Protocol";
    public static final String totalSize = "totalSize";

    public static ArrayList<HashMap<String, String>> rows = new ArrayList<>();
    public static ArrayList<String> detailedView = new ArrayList<>();
    public static ArrayList<String> hexaView = new ArrayList<>();
    public static int number = 0;
    public static final double startTimeInSeconds = getCurrentTime();
    public static boolean captureStart = false;

    public static double getCurrentTime() {
        return System.currentTimeMillis() / 1000.0;
    }

    public void testCap() {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.ERROR || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description
                    = (device.getDescription() != null) ? device.getDescription()
                    : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        System.out.println("Enter Device number");
        Scanner sc = new Scanner(System.in);
        PcapIf device = alldevs.get(2); // We know we have atleast 1 device  
        System.out.printf("Choosing '%s':\n",
                (device.getDescription() != null) ? device.getDescription()
                : device.getName());

        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 60 * 1000;           // 60 seconds in millis  
        Pcap pcap
                = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            @Override
            public void nextPacket(PcapPacket packet, String user) {
                //http example  

                Ethernet eth = new Ethernet();
                Http http = new Http();
                Tcp tcp = new Tcp();
                Ip4 ip = new Ip4();
                Arp arp = new Arp();
                Udp udp = new Udp();
                HashMap<String, String> row = new HashMap<>();
                if ((packet.hasHeader(arp) && packet.hasHeader(eth)) || (packet.hasHeader(ip) && (packet.hasHeader(tcp) || packet.hasHeader(udp)))) {
                    Wireshark.detailedView.add(packet.toString());
                    Wireshark.hexaView.add(packet.toHexdump());
                    Wireshark.rows.add(row);
                    row.put(Wireshark.Number, Wireshark.number + "");
                    row.put(Wireshark.Time, (Wireshark.getCurrentTime() - Wireshark.startTimeInSeconds) + "");
                    row.put(Wireshark.totalSize, packet.getTotalSize() + "");
                }
                if (packet.hasHeader(arp) && packet.hasHeader(eth)) {
                    row.put(Wireshark.Source, FormatUtils.mac(eth.source()));
                    row.put(Wireshark.Destination, FormatUtils.mac(eth.destination()));
                    row.put(Wireshark.Protocol, "ARP");
                } else if (packet.hasHeader(ip)) {
                    row.put(Wireshark.Source, FormatUtils.ip(ip.source()));
                    row.put(Wireshark.Destination, FormatUtils.ip(ip.destination()));
                    if (packet.hasHeader(udp)) {
                        row.put(Wireshark.Protocol, "UDP");
                    } else if (packet.hasHeader(tcp)) {
                        row.put(Wireshark.Protocol, "TCP");
                        if (packet.hasHeader(http) && !http.isResponse()) {
                            row.put(Wireshark.Protocol, "HTTP");
                        }else{
                            int contentLength = Integer.parseInt(http.fieldValue(Http.Response.Content_Length));
                            if(http.getPayload().length<contentLength){
                                HttpHandler.initiateHttpPacket(number, tcp.seq(), tcp.getPayloadLength()+tcp.getPayloadOffset(), contentLength, http.getPayload());
                            }
                        }
                        String str = HttpHandler.handleForHttpIfExpected(tcp.seq(), tcp.getPayloadOffset()+tcp.getPayloadLength(), number, tcp.getPayload());
                        if(str!=null){
                            System.out.println(str);
                            row.put(Wireshark.Protocol, "HTTP");
                        }
                    }
                }

                number++;
            }
        };

        pcap.loop(1000, jpacketHandler, "hi");
        int ll = 0;
        for (HashMap<String, String> row : rows) {
            System.out.println(detailedView.get(ll));;
            for(String value : row.values()) {
                System.out.println(value);
            }
            ll++;
            System.out.println("\n\n\n");
        }
    }

    @Override
    public void start(Stage stage) throws Exception {
//        Parent root = FXMLLoader.load(getClass().getResource("FXMLDocument.fxml"));
//        
//        Scene scene = new Scene(root);
//        
//        stage.setScene(scene);
//        stage.show();
        testCap();

    }

}
