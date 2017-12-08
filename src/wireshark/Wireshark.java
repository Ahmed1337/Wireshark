/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ListView;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author Ahmed
 */
public class Wireshark extends Application {

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
        PcapIf device = alldevs.get(sc.nextInt());
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

            Http http = new Http();

            Tcp tcp = new Tcp();
            Ip4 ip = new Ip4();

            long millis = System.currentTimeMillis();
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                //http example  

                byte[] data;
                if (packet.hasHeader(http)) {
                    data = packet.getByteArray(0, packet.size());
//                    System.out.println(new String(http.getPayload()));
//                    System.out.println(new String(data));
                    //System.out.println(new String(data, 20, data.length - 20));
                    System.out.println(packet.getCaptureHeader().timestampInMillis() - millis);

                }

//                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
//                        new Date(packet.getCaptureHeader().timestampInMillis()),
//                        packet.getCaptureHeader().caplen(), // Length actually captured  
//                        packet.getCaptureHeader().wirelen(), // Original length   
//                        user // User supplied object  
//                );
            }
        };

        pcap.loop(10000, jpacketHandler, "hi");
    }

    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("FXMLDocument.fxml"));

        Scene scene = new Scene(root);

        stage.setScene(scene);
        stage.setTitle("WIRESHARKELGAMED");
        stage.sizeToScene();
        stage.centerOnScreen();
        stage.show();

//
//        testCap();
    }

}
