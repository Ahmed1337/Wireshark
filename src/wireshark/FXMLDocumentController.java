/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.net.URL;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
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
            int packetNumber = tableData.get(table.getSelectionModel().getSelectedIndex()).getNo();
            //String [][] detailedData = getDetailedData(packetNumber);
            //setAccordion(delatiledData);
            hexView.setText(capturer.getHex(packetNumber));
        } catch (Exception e) {
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        //function that returns a list of devices        
        captureVBox.setVisible(false);
        container.setPrefSize(devicesVBox.getPrefWidth(), devicesVBox.getPrefHeight() + MENUHEIGHT);
        tableData = FXCollections.observableArrayList();
        table.setItems(tableData);
        capturer = new Capturer(this);
        devicesList.setItems(FXCollections.observableList(capturer.getDevices()));
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

    protected void addToTable(List row) {
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
