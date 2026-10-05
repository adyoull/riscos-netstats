# Changelog

## 1.06-rc2 (05 Oct 2026)
- Connections on the Internet 5 stack: its `inetstat` labels every
  socket "ip", so 1.05 and rc1 did not recognise the lines and showed
  them as raw text, which did not line up. Any socket line is now
  recognised (a line with a state counts as TCP; others are counted as
  "other"), and the UNIX domain socket list that follows is left out.
- Connections: wider gaps between the columns.

## 1.06-rc1 (05 Oct 2026)
- Connections: the columns are sized to fit their contents, measured in
  the desktop font, so they line up with the headings and with each
  other whatever the font and however long the addresses (IPv6
  addresses included). The window's work area widens to fit.
- Tab characters in `inetstat` output are treated as spaces.
- Correction to 1.05: TaskWindow_Output does not need acknowledging.
  The ROOL PRM wiki says it does, but the TaskWindow module sends it as
  an ordinary message (thanks to Matthew Phillips and Steve Fryatt).
  The acknowledgement code never ran and has been removed.

## 1.05 (04 Oct 2026)
- New **Data usage** window: this session, today, this month, the last
  14 days and 12 months (counted while NetStats runs; saved in
  `<Choices$Write>.NetStats.Usage`). Menu: "Reset session totals".
- New **Network** window: host name, domain, DNS servers, default
  gateway and the routing table. It updates itself every 5 seconds and
  shows when it last did; click to update at once.
- **Interface** submenu: show all interfaces or just one in the Monitor
  and on the icon bar (saved in Choices).
- Windows only redraw the lines that changed, so they no longer flicker
  once a second, and text is only built for open windows.
- TaskWindow_Output messages are now acknowledged, as the PRM asks
  (wrong: see 1.06). Task handles are passed to TaskWindow as 8 hex digits. The program
  information fields are display fields.
- WimpSlot raised to 512K.
- Test builds 1.05-rc1 to rc3 led up to this release.

## 1.04 (04 Oct 2026)
- Connections: the Recv-Q and Send-Q headings no longer overlap (wider
  queue columns; the window opens wider).
- The "About this program" window now looks like other RISC OS
  programs': "Name:" style labels and grey display fields with a sunken
  border, and a Licence row.

## 1.03 (03 Oct 2026)
- The current download and upload rates are shown under the icon bar icon
  ("v1.2M ^34K"). Menu option "Rates on icon bar" turns this off.
- Choices: the menu options, which windows are open and where they are
  are saved in `<Choices$Write>.NetStats.Choices` and restored next time.

## 1.02 (03 Oct 2026)
- The menu ticks the windows that are open. Choosing a ticked window
  closes it.

## 1.01 (03 Oct 2026)
- Connections runs `inetstat -an` in a TaskWindow. No command window
  appears any more, and the desktop keeps running while it works.

## 1.00 (03 Oct 2026)
- First version: Monitor, Interfaces, Protocols and Connections windows.
  Reads the ROD stack through Socket_Sysctl; falls back to the old
  method on Internet 5.
