function do_confirm(str) {
	if(confirm('Are you sure to ' + str + ' ?')) {
		return true;
	} else {
		return false;
	}
}