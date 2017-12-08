/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Accordion;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.VBox;
import javafx.scene.control.TitledPane;
import javafx.stage.WindowEvent;

/**
 *
 * @author Ahmed
 */
public class FXMLDocumentController implements Initializable {

    @FXML

    private Label label;
    @FXML
    private ListView list;
    @FXML
    private VBox captureVBox;
    @FXML
    private VBox vbox2;
    @FXML
    private AnchorPane anchorPane;
    @FXML
    private TableView table;

    private static final int MENUHEIGHT = 25;

    private ObservableList<TableItem> tableData;
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
    private Capturer capturer;

    private int deviceNumber;

    private void disableButtons(boolean start, boolean stop) {
        startButton.setDisable(start);
        stopButton.setDisable(stop);
        restartButton.setDisable(stop);
    }

    @FXML
    private void handleStartButton(Event event) {
        tableData = FXCollections.observableArrayList();
        table.setItems(tableData);
        capturer = new Capturer(this);
        capturer.getDevices();
        this.startCapturing();
        disableButtons(true, false);
    }

    @FXML
    private void handleStopButton(Event event) {
        capturer.stopCapturing();
        disableButtons(false, true);
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
            deviceNumber = list.getSelectionModel().getSelectedIndex();
            if (deviceNumber == -1) {
                return;
            }
            startCapturing();
            captureVBox.setVisible(false);
            vbox2.setVisible(true);
            anchorPane.setPrefSize(vbox2.getPrefWidth(), vbox2.getPrefHeight() + MENUHEIGHT); //majornelson <3
            anchorPane.getScene().getWindow().sizeToScene();
            anchorPane.getScene().getWindow().centerOnScreen();
            anchorPane.getScene().getWindow().setOnCloseRequest(new EventHandler<WindowEvent>() {
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
            int packetNumber = Integer.parseInt(tableData.get(table.getSelectionModel().getSelectedIndex()).getNo());
            //String [][] detailedData = getDetailedData(packetNumber);
            //setAccordion(delatiledData);
            hexView.setText(capturer.getHex(packetNumber));
        } catch (Exception e) {
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        //function that returns a list of devices        
        vbox2.setVisible(false);
        anchorPane.setPrefSize(captureVBox.getPrefWidth(), captureVBox.getPrefHeight() + MENUHEIGHT);
        tableData = FXCollections.observableArrayList();
        table.setItems(tableData);
        capturer = new Capturer(this);
        list.setItems(FXCollections.observableList(capturer.getDevices()));
    }

    private void startCapturing() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                capturer.startCapturing(deviceNumber);
            }

        });
        t.start();
    }

    protected void addToTable(List<String> row) {
        if (row.size() == 7) {
            tableData.add(new TableItem(row));
        } else {
            System.out.println(Arrays.toString(row.toArray()));
        }

    }

    private void setAccordion(String[][] detailedData) {
        int i = 0;
        for (TitledPane titledPane : accordion.getPanes()) {
            if (i < detailedData.length) {
                titledPane.setText(detailedData[i][0]);
                ((TextArea) titledPane.getContent()).setText(detailedData[i][1]);
                titledPane.setVisible(true);
            } else {
                titledPane.setVisible(false);
            }
            i++;

        }
    }

    public static class TableItem {

        private final SimpleStringProperty no;
        private final SimpleStringProperty time;
        private final SimpleStringProperty source;
        private final SimpleStringProperty destination;
        private final SimpleStringProperty protocol;
        private final SimpleStringProperty length;
        private final SimpleStringProperty info;

        private TableItem(List<String> data) {
            no = new SimpleStringProperty(data.get(0));
            time = new SimpleStringProperty(data.get(1).substring(0, data.get(1).indexOf(".") + 6));
            source = new SimpleStringProperty(data.get(2));
            destination = new SimpleStringProperty(data.get(3));
            protocol = new SimpleStringProperty(data.get(4));
            length = new SimpleStringProperty(data.get(5));
            info = new SimpleStringProperty(data.get(6));
        }

        public String getNo() {
            return no.get();
        }

        public String getTime() {
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

        public String getLength() {
            return length.get();
        }

        public String getInfo() {
            return info.get();
        }

    }

}
