class WritePassTime {
	#more concise way to format elapsed time in human readable format
	static [string] ToSentence([datetime]$sdt) {
		$t = New-TimeSpan -Start $sdt #-End = Now() by default
		return "Info: Script total runtime is $($t.Hours) hours, $($t.Minutes) minutes and $($t.Seconds) seconds"
	}
}
