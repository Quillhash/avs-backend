const web3 = new Web3(new Web3.providers.WebsocketProvider('YOUR_INFURA_URL'));

// Replace these with your contract details
const contractAddress = 'CONTRACT_ADDRESS';
const contractABI = CONTRACT_ABI;

const contract = new web3.eth.Contract(contractABI, contractAddress);

const eventsContainer = document.getElementById('events');

// Function to add event to frontend
function addEventToFrontend(event) {
    const eventDiv = document.createElement('div');
    eventDiv.className = 'event';
    eventDiv.textContent = JSON.stringify(event.returnValues, null, 2);
    eventsContainer.appendChild(eventDiv);
}

// Start listening to events
contract.events
    .YourEventName({
        fromBlock: 'latest',
    })
    .on('data', (event) => {
        addEventToFrontend(event);
        console.log("Event received:", event);
    })
    .on('error', (error) => console.error("Error:", error));
