/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.lang.reflect.Field;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

/**
 *
 * @author Ahmed
 */
public class Wireshark extends Application {

    private void loadDLL() throws Exception {
        System.setProperty("java.library.path", "lib/");
        Field fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
        fieldSysPath.setAccessible(true);
        fieldSysPath.set(null, null);
    }

    @Override
    public void start(Stage stage) throws Exception {
        loadDLL();
        Parent root = FXMLLoader.load(getClass().getResource("FXMLDocument.fxml"));
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.setTitle("WireWhale");
        stage.getIcons().add(new Image(getClass().getClassLoader().getResourceAsStream("images/wireshark.png")));
        stage.show();

    }

    public static void main(String[] args) {
        launch(args);
    }
}
