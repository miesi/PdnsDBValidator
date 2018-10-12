/*
 $Id: DomainUpdater.java 5692 2014-11-12 17:23:37Z jjungermann $
 */
package de.mieslinger.pdnsdbvalidator;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.TXTRecord;

/**
 *
 * @author mieslingert
 */
public class DomainUpdater {

    private ConcurrentLinkedQueue<Long> shortDomainQ;
    private ConcurrentLinkedQueue<String> logFileQ;
    private ConcurrentLinkedQueue<String> criticalLogFileQ;
    private ThreadPoolExecutor threadPool = null;
    final LinkedBlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>();
    private volatile boolean keepOnRunning = true;

    private DomainUpdater() {
    }

    public DomainUpdater(ConcurrentLinkedQueue<Long> shortDomainQ,
            ConcurrentLinkedQueue<String> logFileQ,
            ConcurrentLinkedQueue<String> criticalLogFileQ,
            int fixedPoolSize) throws Exception {

        this.shortDomainQ = shortDomainQ;
        this.logFileQ = logFileQ;
        this.criticalLogFileQ = criticalLogFileQ;

        threadPool = (ThreadPoolExecutor) Executors.newFixedThreadPool(fixedPoolSize);
        for (int i = 1; i < fixedPoolSize; i++) {
            threadPool.execute(new ShortDomainUpdaterWorker(shortDomainQ, logFileQ, criticalLogFileQ));
        }
    }

    public void shutdown() {
        this.keepOnRunning = false;
    }

    private class ShortDomainUpdaterWorker implements Runnable {

        private ConcurrentLinkedQueue<Long> domainIdQ;
        private ConcurrentLinkedQueue<String> logFileQ;
        private ConcurrentLinkedQueue<String> criticalLogFileQ;
        private volatile boolean keepOnRunning = true;
        private Connection cn = null;

        private PreparedStatement getSOARecord = null;
        //private PreparedStatement updSOARecord = null;
        //private PreparedStatement insSOARecord = null;
        private PreparedStatement getNameFromDomains = null;

        private PreparedStatement getTXTRecords = null;
        //private PreparedStatement updTXTRecord = null;
        //private PreparedStatement delTXTRecord = null;

        private PreparedStatement getAAAARecords = null;

        //private PreparedStatement delJabberRecords = null;
        //private PreparedStatement getRecords = null;
        private PreparedStatement insBroken = null;

        private int updatedDomains = 0;
        private final int batchSize = 500;

        private ShortDomainUpdaterWorker() {
        }

        public ShortDomainUpdaterWorker(ConcurrentLinkedQueue<Long> DomainIdQ,
                ConcurrentLinkedQueue<String> logFileQ, ConcurrentLinkedQueue<String> criticalLogFileQ) throws Exception {

            this.domainIdQ = DomainIdQ;
            this.logFileQ = logFileQ;
            this.criticalLogFileQ = criticalLogFileQ;

            // prepare SQL
            Class.forName(DataBase.getJdbcClass());
            cn = DriverManager.getConnection(DataBase.getJdbcUrl(), DataBase.getDbUser(), DataBase.getDbPass());
            cn.setAutoCommit(false);
            // SOA fix statements
            // check SOA exists and is valid
            getNameFromDomains = cn.prepareStatement("select name from domains where id=?");

            getSOARecord = cn.prepareStatement("select name, content from records where domain_id=? and type='SOA'");
            //updSOARecord = cn.prepareStatement("update records set content=?, ttl = 86400 where domain_id=? and type='SOA'");
            //insSOARecord = cn.prepareStatement("insert into records(domain_id, name, type, content, ttl, rev_name) values (?,?,?,?,?,reverse(?))");

            // TXT Records
            // select, if contains '"' transform to dnsjava object, log deletion
            getTXTRecords = cn.prepareStatement("select id, name, content from records where domain_id=? and type='TXT'");
            // only list TXT records, no auto fix
            //updTXTRecord = cn.prepareStatement("update records set content = ? where id = ?");
            //delTXTRecord = cn.prepareStatement("delete from records where id=?");
            // AAAA Records
            // select, check whether the string in content is a valid IPv6 address
            getAAAARecords = cn.prepareStatement("select id, name, content from records where domain_id=? and type='AAAA'");
            //delAAAARecord = cn.prepareStatement("delete from records where id=?");
            // jabber fix
            //delJabberRecords = cn.prepareStatement("delete from records where domain_id=? and type = 'SRV' and content = ?");

            insBroken = cn.prepareStatement("insert into domainmetadata(domain_id, kind, content) values (?, ?, ?)");

        }

        public void run() {
            while (keepOnRunning) {
                ResultSet rs = null;
                String zoneName = null;
                Long domainId = domainIdQ.poll();
                if (domainId != null) {
                    updatedDomains++;
                    try {
                        // FIX or insert SOA if broken or missing
                        getSOARecord.setLong(1, domainId);
                        rs = getSOARecord.executeQuery();
                        if (rs.next()) {
                            do {
                                zoneName = rs.getString(1);
                                if (zoneName.equals("")) {
                                    setDomainIdBroken(insBroken, domainId, "SOA name does not match domainstable name");
                                }
                                String soa = rs.getString(2);
                                String[] soaFields = soa.split(" ");

                                if (soaFields.length != 7) {
                                    setDomainIdBroken(insBroken, domainId, "SOA invalid");
                                }
                            } while (rs.next());
                        }
                        try {
                            rs.close();
                        } catch (SQLException e) {
                        }

                        // TXT
                        // list broken TXT records
                        getTXTRecords.setLong(1, domainId);
                        rs = getTXTRecords.executeQuery();
                        while (rs.next()) {
                            long rrId = rs.getLong(1);
                            Name rrName = new Name(rs.getString(2) + ".");
                            String rrContent = rs.getString(3);
                            //logFileQ.add("domain_id: " + domainId + " zone: " + zoneName + "rrName: " + rrName.toString() + " type TXT rrContent: " + rrContent);
                            TXTRecord tr = null;
                            try {

                                tr = new TXTRecord(rrName, DClass.IN, 3600, rrContent);

                            } catch (Exception e) {
                                setDomainIdBroken(insBroken, domainId, "TXT inavlid");
                                continue;
                            }
                        }
                        try {
                            rs.close();
                        } catch (SQLException e) {
                        } // TXT

                        // AAAA
                        // identify broken AAAA reords
                        getAAAARecords.setLong(1, domainId);
                        rs = getAAAARecords.executeQuery();
                        while (rs.next()) {
                            long rrId = rs.getLong(1);
                            Name rrName = new Name(rs.getString(2) + ".");
                            String rrContent = rs.getString(3);
                            //logFileQ.add("domain_id: " + domainId + " zone: " + zoneName + "rrName: " + rrName.toString() + " type TXT rrContent: " + rrContent);
                            AAAARecord aAAAr = null;
                            try {
                                InetAddress ip6 = InetAddress.getByName(rrContent);
                                aAAAr = new AAAARecord(rrName, DClass.IN, 3600, ip6);
                                aAAAr.toString();
                            } catch (Exception e) {
                                setDomainIdBroken(insBroken, domainId, "AAAA invalid");
                                continue;
                            }
                        }
                        try {
                            rs.close();
                        } catch (SQLException e) {
                        } // AAAA

                        // Do the commit
                        if (updatedDomains > batchSize) {
                            cn.commit();
                            updatedDomains = 0;
                            logFileQ.add("domain_id: " + domainId + " " + zoneName + " commit send");
                        }
                    } catch (Exception e) {
                        criticalLogFileQ.add("domain_id: " + domainId + " " + zoneName + " exception: " + e.getMessage());
                        e.printStackTrace();
                    }
                } else {
                    try {
                        logFileQ.add("domain_id: " + domainId + " commit send, sleeping");
                        cn.commit();
                        updatedDomains = 0;
                        Thread.sleep(500);
                        logFileQ.add("domain_id: " + domainId + " commit sleep finished");
                    } catch (Exception e) {
                        criticalLogFileQ.add("domain_id: " + domainId + " commit exception: " + e.getMessage());
                        System.out.println("domain_id: " + domainId + " commit exception: " + e.getMessage());
                    }
                }
            }
        }
    }

    public String join(String r[], String d) {
        if (r.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int i;
        for (i = 0; i < r.length - 1; i++) {
            sb.append(r[i] + d);
        }
        return sb.toString() + r[i];
    }

    private void deleteBullshit(Connection cn, long domainId) {
        try {
            criticalLogFileQ.add("domainId: " + domainId + " delete bogus domain");
            PreparedStatement delDomain = cn.prepareStatement("delete from domains where id=?");
            delDomain.executeUpdate();
            delDomain.close();
        } catch (Exception e) {
        }
    }

    private void setDomainIdBroken(PreparedStatement insBroken, long domainId, String reason) {
        try {
            insBroken.setLong(1, domainId);
            insBroken.setString(2, "broken");
            insBroken.setString(3, reason);
            insBroken.execute();
        } catch (Exception e) {

        }
    }

    private void setDomainIdBroken(PreparedStatement insBroken, long domainId) {
        try {
            insBroken.setLong(1, domainId);
            insBroken.setString(2, "broken");
            insBroken.setString(3, "some Reason");
            insBroken.execute();
        } catch (Exception e) {

        }
    }

    private void debugDomainId(Connection cn, long domainId, String reason) {
        // dump data of potentially invalid zones/domains
        try {
            StringBuilder sb = new StringBuilder();

            sb.append("domainId: " + domainId + " debug reason: " + reason + "\n");
            PreparedStatement getDomain = cn.prepareStatement("select name from domains where id=?");

            ResultSet rs = null;
            String domainName = null;
            getDomain.setLong(1, domainId);
            rs = getDomain.executeQuery();
            while (rs.next()) {
                domainName = rs.getString(1);
                sb.append(String.format("domains id: %d Name: |%s|\n", domainId, domainName));

            }
            rs.close();
            getDomain.close();

            PreparedStatement getRecords = cn.prepareStatement("select name, type, content from records where domain_id=?");
            getRecords.setLong(1, domainId);
            rs = getRecords.executeQuery();
            while (rs.next()) {
                sb.append(String.format("records domain_id: %d |%s|%s|%s|\n", domainId, rs.getString(1), rs.getString(2), rs.getString(3)));
            }
            rs.close();
            sb.append("-----\n");
            criticalLogFileQ.add(sb.toString());
            getRecords.close();
        } catch (Exception e) {
        }
    }
}
