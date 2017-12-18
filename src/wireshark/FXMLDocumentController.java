/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.awt.Color;
import java.io.File;
import java.net.URL;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleFloatProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Accordion;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.VBox;
import javafx.scene.control.TitledPane;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import javafx.util.Callback;

//importing menu bar and items
import javafx.scene.control.MenuBar;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuItem;
import javafx.event.ActionEvent;
import javafx.stage.FileChooser;
import javafx.scene.control.Dialog;

/**
 *
 * @author Ahmed
 */
public class FXMLDocumentController implements Initializable {

    @FXML
    private ListView devicesList;
    @FXML
    private VBox devicesVBox;
    @FXML
    private VBox captureVBox;
    @FXML
    private AnchorPane container;
    @FXML
    private TableView table;

    private static final int MENUHEIGHT = 25;

    private ObservableList<TableItem> tableData;
    private ObservableList<TableItem> filteredTableData;
    @FXML
    private Accordion accordion;
    @FXML
    private TextArea hexView;

    @FXML
    private Button startButton;
    @FXML
    private Button stopButton;
    @FXML
    private Button restartButton;

    @FXML
    private TextField filterTextField;
    @FXML
    private Label errorLabel;

    private Capturer capturer;

    private int deviceNumber;

    private List<String> allowedProtocols;
    private List<String> allowedIPs;
    private static final String[] PROTOCOLS = {"tcp", "udp", "http", "arp", "dns", "icmp"};
    private static final String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
    //private static final String ipv6Pattern = "([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}";

    private void disableButtons(boolean start, boolean stop) {
        startButton.setDisable(start);
        stopButton.setDisable(stop);
        restartButton.setDisable(stop);
    }

    //load in GUI code
    @FXML
    private void OpenMenuItemHandler(ActionEvent event) {
        FileChooser fc = new FileChooser();
        File selectedFile = fc.showOpenDialog(null);
        if (selectedFile.exists()) {
            String fileToOpen = selectedFile.getAbsolutePath();
            if (fileToOpen.substring(fileToOpen.indexOf(".")).equals(".pcap")) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        capturer.Load(fileToOpen);
                    }
                });
                thread.start();
                //Change interface gui
            } else {
                //27otaha fe messgebox

                System.out.println("must open .pcap file only");
            }
        } else {
            System.out.println("can't open file");
        }
    }

    //save in GUI code
    @FXML
    private void SavingHandler(Event event) {
        this.capturer.Save();
    }

    @FXML
    private void handleFilterTextField(KeyEvent event) {
        if (event.getCode() == KeyCode.ENTER) {
            String[] filters = filterTextField.getText().split(";");
            allowedProtocols.clear();
            allowedIPs.clear();
            if (filters.length == 1 && filters[0].isEmpty()) {
                errorLabel.setText("");
            } else {
                for (String filter : filters) {
                    if (isProtocol(filter)) {
                        allowedProtocols.add(filter);
                        errorLabel.setText("");
                    } else if (isIP(filter)) {
                        allowedIPs.add(filter);
                        errorLabel.setText("");
                    } else {
                        errorLabel.setText("Invalid Syntax");
                    }
                }
            }
            this.refreshTable();
            this.resetView();
        }
    }

    @FXML
    private void handleStartButton(Event event) {
        this.resetTable();
        this.resetView();
        capturer = new Capturer(this);
        capturer.getDevices();
        this.startCapturing();
        disableButtons(true, false);
        ((Stage) container.getScene().getWindow()).setTitle("Capturing packets...");
    }

    @FXML
    private void handleStopButton(Event event) {
        this.SavingHandler(event);
        capturer.stopCapturing();
        disableButtons(false, true);
        ((Stage) container.getScene().getWindow()).setTitle("Stopped capturing");
    }

    @FXML
    private void handleRestartButton(Event event) {
        handleStopButton(event);
        handleStartButton(event);
    }

    @FXML
    private void handleMouseClicked(MouseEvent click) {
        if (click.getClickCount() == 2) {
            //choose device by index
            deviceNumber = devicesList.getSelectionModel().getSelectedIndex();
            if (deviceNumber == -1) {
                return;
            }
            startCapturing();
            devicesVBox.setVisible(false);
            captureVBox.setVisible(true);
            container.setPrefSize(captureVBox.getPrefWidth(), captureVBox.getPrefHeight() + MENUHEIGHT); //majornelson <3
            container.getScene().getWindow().sizeToScene();
            container.getScene().getWindow().centerOnScreen();
            ((Stage) container.getScene().getWindow()).setTitle("Capturing packets...");
            container.getScene().getWindow().setOnCloseRequest(new EventHandler<WindowEvent>() {
                @Override
                public void handle(WindowEvent event) {
                    capturer.stopCapturing();
                }

            }
            );
        }
    }

    @FXML
    private void handleTableMouseClick(Event Click) {
        try {
            int packetNumber = filteredTableData.get(table.getSelectionModel().getSelectedIndex()).getNo();
            setAccordion(getDetailedData(packetNumber));
            hexView.setText(capturer.getHex(packetNumber));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void resetTable() {
        tableData.clear();
        filteredTableData.clear();
    }

    private void refreshTable() {
        filteredTableData.clear();
        for (TableItem item : tableData) {
            addtoFilteredTable(item);
        }
    }

    private void resetView() {
        for (TitledPane titledPane : accordion.getPanes()) {
            titledPane.setVisible(false);
        }
        hexView.setText(null);
    }

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        //function that returns a list of devices
        captureVBox.setVisible(false);
        container.setPrefSize(devicesVBox.getPrefWidth(), devicesVBox.getPrefHeight() + MENUHEIGHT);
        tableData = FXCollections.synchronizedObservableList(FXCollections.observableArrayList());
        filteredTableData = FXCollections.synchronizedObservableList(FXCollections.observableArrayList());
        table.setItems(filteredTableData);
        capturer = new Capturer(this);
        devicesList.setItems(FXCollections.observableList(capturer.getDevices()));
        allowedProtocols = new ArrayList();
        allowedIPs = new ArrayList();
    }

    private boolean isIP(String s) {
        return s.matches(ipv4Pattern);
    }

    private boolean isProtocol(String s) {
        for (String protocol : PROTOCOLS) {
            if (s.equals(protocol)) {
                return true;
            }
        }
        return false;
    }

    private boolean isIPAllowed(String ip) {
        if (!allowedIPs.isEmpty()) {
            return allowedIPs.contains(ip);
        } else {
            return true;
        }
    }

    private boolean isProtocolAllowed(String protocol) {
        if (!allowedProtocols.isEmpty()) {
            return allowedProtocols.contains(protocol.toLowerCase());
        } else {
            return true;
        }
    }

    private void startCapturing() {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                capturer.startCapturing(deviceNumber);
            }
        });
        thread.start();
    }

    private void addtoFilteredTable(TableItem item) {
        if (isProtocolAllowed(item.getProtocol()) && (isIPAllowed(item.getDestination()) || isIPAllowed(item.getSource()))) {
            filteredTableData.add(item);
        }
    }

    protected void addtoTable(List row) {
        if (row.size() == 7) {
            TableItem item = new TableItem(row);
            Platform.runLater(new Runnable() {
                @Override
                public void run() {
                    tableData.add(item);
                    addtoFilteredTable(item);
                }
            });

        } else {
            System.out.println(Arrays.toString(row.toArray()));
        }
    }

    protected ArrayList<String[]> getDetailedData(int packetNum) {
        String data = capturer.getDetailedData(packetNum).trim(), header = null, text = null;
        int index = 0;
        int isDNS = data.indexOf("DNS-information");
        ArrayList<String[]> ret = new ArrayList();
        while (index < data.length() - 1) {
            if (index == isDNS + 1 && index > 0) {
                break;
            }
            String[] accordion = new String[2];
            //System.out.println(data.charAt(index));
            header = data.substring(index, index = data.indexOf(":", index));
            boolean isFrame = false;
            String temp = "";
            if (data.charAt(index + 1) == '\n') {
                isFrame = true;
                index++;
            } else {
                temp += data.substring(index, index = data.indexOf(header + ":", index + 1));
                temp = temp.substring(0, temp.indexOf("*")) + temp.substring(temp.lastIndexOf("*") + 1, temp.length());
                index += header.length() + 8;
            }
            int finalIndex = 0;
            if (header.equals("Data")) {
                break;
            } else if (header.equals("Html")) {
                finalIndex = data.length();
            } else if (header.equals("Rtp")) {
                finalIndex = data.lastIndexOf(header);
            } else {
                finalIndex = data.lastIndexOf(header + ":");
            }
            text = data.substring(index, index = finalIndex);
            text = text.replaceAll(header + ":", "");
            index += header.length() + ((isFrame) ? 2 : 3);
            if (header.equals("Rtp")) {
                index -= 2;
            }
            if (isFrame) {
                header += (" " + packetNum);
            } else {
                header += temp;
            }
            accordion[0] = header;
            accordion[1] = text;
            ret.add(accordion);
            //System.out.println(data.substring(index));
            //System.out.println("hi\n"+data.substring(index));
        }
        if ((index = data.indexOf("HTTP-reassembly")) > -1) {
            String[] accordion = new String[2];
            accordion[0] = "Html";
            accordion[1] = data.substring(index + "HTTP-reassembly".length(), index = data.indexOf("\n\nHttp packet is assembled from the following tcp packets\n\n"));
            ret.add(accordion);
            accordion = new String[2];
            accordion[0] = "Reassembled TCP segments";
            accordion[1] = data.substring(index + "\n\nHttp packet is assembled from the following tcp packets\n\n".length(), data.length() - 1);
            ret.add(accordion);
        } else if ((index = isDNS) > -1) {
            String[] accordion = new String[2];
            header = data.substring(index + "DNS-information".length() + 1, index = data.indexOf("]", index));
            index++;
            accordion[0] = header;
            accordion[1] = data.substring(index, data.length() - 1);
            ret.add(accordion);
        }
        return ret;
    }

    private void setAccordion(ArrayList<String[]> detailedData) {
        int i = 0;
        for (TitledPane titledPane : accordion.getPanes()) {
            if (i < detailedData.size()) {
                titledPane.setText(detailedData.get(i)[0]);
                ((TextArea) titledPane.getContent()).setText(detailedData.get(i)[1]);
                titledPane.setVisible(true);
            } else {
                titledPane.setVisible(false);
            }
            i++;

        }
    }

    public static class TableItem {

        private final SimpleIntegerProperty no;
        private final SimpleDoubleProperty time;
        private final SimpleStringProperty source;
        private final SimpleStringProperty destination;
        private final SimpleStringProperty protocol;
        private final SimpleIntegerProperty length;
        private final SimpleStringProperty info;

        private TableItem(List data) {
            no = new SimpleIntegerProperty((int) data.get(0));
            time = new SimpleDoubleProperty((double) data.get(1));
            source = new SimpleStringProperty((String) data.get(2));
            destination = new SimpleStringProperty((String) data.get(3));
            protocol = new SimpleStringProperty((String) data.get(4));
            length = new SimpleIntegerProperty((int) data.get(5));
            info = new SimpleStringProperty((String) data.get(6));
        }

        public Integer getNo() {
            return no.get();
        }

        public Double getTime() {
            return time.get();
        }

        public String getSource() {
            return source.get();
        }

        public String getDestination() {
            return destination.get();
        }

        public String getProtocol() {
            return protocol.get();
        }

        public Integer getLength() {
            return length.get();
        }

        public String getInfo() {
            return info.get();
        }

    }

}
