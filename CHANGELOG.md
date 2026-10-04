# Changelog

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
