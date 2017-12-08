/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

/**
 *
 * @author fadia
 */
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
public class HttpHelperData {
    ArrayList<String> tcpPacksNums  = new ArrayList<>();
    byte[] content;
    int contentLeft;
    
    
    public HttpHelperData(int contentLength, int firstNum, byte[] firstContentPiece) {
        this.content = Arrays.copyOf(firstContentPiece, firstContentPiece.length);
        this.contentLeft = contentLength - firstContentPiece.length;
        tcpPacksNums.add(firstNum+"");
    }
    public String handleExpectedSeqNum(int num, byte[] contentPiece){
        contentLeft -= contentPiece.length;
        tcpPacksNums.add(num+"");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try {
            outputStream.write(content);
            outputStream.write(contentPiece);
        } catch (IOException ex) {System.err.println("Exception happened when concating http content");}
        content = outputStream.toByteArray();
        if(contentLeft == 0){
            String res = new String(content)+"\n\nHttp packet is assembled from the following tcp packets\n\n";
            for(String str : tcpPacksNums){
                res+="TCP packet #"+str+"\n";
            }
            return res;
        }else{
            return "more";
        }
    }
}
