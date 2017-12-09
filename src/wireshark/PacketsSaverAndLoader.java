package wireshark;

/**
 *
 * @author karimm7mad
 */

import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import java.util.Date;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;  

public class PacketsSaverAndLoader {

    //public for easy access
    public String fileName;
    private PcapDumper dumper; 
    private PcapHandler<PcapDumper> dumpHandler; //for handling dumping packets
    private final StringBuilder offlineErrBuffer = new StringBuilder(); // For any error msgs  

    public PacketsSaverAndLoader() {
        this.dumpHandler = new PcapHandler<PcapDumper>() {
            public void nextPacket(PcapDumper dumper, long seconds, int useconds,int caplen, int len, ByteBuffer buffer) {
                dumper.dump(seconds, useconds, caplen, len, buffer);
            }
        };
        
    }
    
    //give it pcap object ( the one called openLive method before ), numOfPackets to store in a file
    public void Save(int numOfPackets,Pcap pcap){
        this.dumper = pcap.dumpOpen("tmp-capture-file.cap");
        pcap.loop(numOfPackets, this.dumpHandler, this.dumper);
        File f = new File(this.fileName);
        //this line is for testing
        //System.out.printf("%s file has %d bytes in it!\n", fileName, f.length());
        dumper.close();
    }
    
    //public void Load(ArrayList<String> buffer){
    public void Load(){
        //1-load offline file
        Pcap pcap = Pcap.openOffline("tmp-capture-file.cap",this.offlineErrBuffer);
        //2-check if all OK
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "+ this.offlineErrBuffer.toString());  
            return;  
        }
        //3-create packet handler
        
        PcapPacketHandler<String> receivedPacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                System.out.printf("Received at %s caplen=%-4d len=%-4d %s\n",   
                    new Date(packet.getCaptureHeader().timestampInMillis()),   
                    packet.getCaptureHeader().caplen(), // Length actually captured  
                    packet.getCaptureHeader().wirelen(), // Original length  
                    user // User supplied object  
                    );  
            }  
        };
        //capture the Packets
        pcap.loop(10, receivedPacketHandler, "jNetPcap rocks!");
    }
    
}
