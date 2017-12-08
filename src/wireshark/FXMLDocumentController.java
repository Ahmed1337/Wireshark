/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.net.URL;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.VBox;

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
    
    private static int MENUHEIGHT = 25;

    @FXML
    private void handleMouseClicked(MouseEvent click) {
        if (click.getClickCount() == 2) {
            //choose device by index
            label.setText(list.getSelectionModel().getSelectedIndex() + "");
            captureVBox.setVisible(false);
            vbox2.setVisible(true);
            anchorPane.setPrefSize(vbox2.getPrefWidth(), vbox2.getPrefHeight() + MENUHEIGHT); //majornelson <3
            anchorPane.getScene().getWindow().sizeToScene();
            anchorPane.getScene().getWindow().centerOnScreen();
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        //function that returns a list of devices
        list.setItems(FXCollections.observableArrayList("Single", "Double", "Suite", "Family App"));
        vbox2.setVisible(false);
        anchorPane.setPrefSize(captureVBox.getPrefWidth(), captureVBox.getPrefHeight() + MENUHEIGHT);
    }

}
