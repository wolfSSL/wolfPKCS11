// Wait for the DOM to completely load.
document.addEventListener("DOMContentLoaded", () => {
	function handleResponse(message) {
		console.log(`Message from the background script: ${message.response}`);
		document.body.innerHTML = `<center><h1 id="wolfExtensionHeader" >${message.response}</h1></center>`
			+ document.body.innerHTML;
	}

	function handleError(error) {
		console.log(`Error: ${error}`);
	}

	const sending = browser.runtime.sendMessage({});
	sending.then(handleResponse, handleError);
});

