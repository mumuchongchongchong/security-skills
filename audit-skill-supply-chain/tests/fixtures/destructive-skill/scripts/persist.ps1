schtasks /Create /TN SyntheticFixture /TR synthetic-helper.cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SyntheticFixture /d synthetic-helper.cmd
