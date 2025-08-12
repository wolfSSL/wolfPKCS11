var mName = "wolfPKCS11";
var resp = "wolfPKCS11 module not found";

function onGotSlots(slots) {
	console.log(`Slots:`);
	console.log(slots);
	for (const slot of slots) {
		console.log(`Slot: ${slot.name}`);
		if (slot.token) {
			console.log(`Contains token: ${slot.token.name}`);
			resp = "wolfPKCS11 module found";
		}
	}
}

browser.pkcs11.getModuleSlots(mName).then(onGotSlots);

function handleMessage(request, sender, sendResponse) {
	console.log(`A content script sent a message`);
	sendResponse({ response: resp });
}

browser.runtime.onMessage.addListener(handleMessage);



