package de.mieslinger.pdnsdbvalidator;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/*
 $Id: DataBase.java 5409 2014-07-22 14:45:22Z mieslingert $
 */
/**
 *
 * @author mieslingert
 */
public class DataBase {

    private static String jdbcUrl = null;
    private static String dbUser = null;
    private static String dbPass = null;
    private static String jdbcClass = null;

    static {
        Properties cduProperties = new Properties();
        try {
            BufferedInputStream stream = new BufferedInputStream(new FileInputStream(System.getProperty("user.home") + "/.pdnsdbvalidator.properties"));
            cduProperties.load(stream);
            stream.close();
        } catch (IOException ex) {
            System.out.println("could not load properties: " + ex.getMessage());
        }
        jdbcUrl = cduProperties.getProperty("jdbcUrl", "jdbc:mysql://127.0.0.1:3306/db?useServerPrepStmts=true");
        dbUser = cduProperties.getProperty("dbUser", "root");
        dbPass = cduProperties.getProperty("dbPass", "");
        jdbcClass = cduProperties.getProperty("jdbcClass", "com.mysql.jdbc.Driver");

    }

    public static String getJdbcUrl() {
        return jdbcUrl;
    }

    public static String getJdbcClass() {
        return jdbcClass;
    }

    public static String getDbUser() {
        return dbUser;
    }

    public static String getDbPass() {
        return dbPass;
    }
}
