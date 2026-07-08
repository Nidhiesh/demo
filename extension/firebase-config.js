import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getFirestore, collection, addDoc, serverTimestamp, query, where, getDocs } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

// Your exact configuration from the screenshot
const firebaseConfig = {
  apiKey: "AIzaSyCPML3kfr84iLnCTFYdqrSB0_hrdwHgh88",
  authDomain: "cybershield-88323.firebaseapp.com",
  projectId: "cybershield-88323",
  storageBucket: "cybershield-88323.firebasestorage.app",
  messagingSenderId: "439105190458",
  appId: "1:439105190458:web:73da13fd84e09793db1303",
  measurementId: "G-FV1YVXJF6G"
};

// 1. Initialize the app
const app = initializeApp(firebaseConfig);

// 2. Initialize the Database (Firestore)
const db = getFirestore(app);

// 3. Hash function for deduplication
function createHash(text) {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash) + text.charCodeAt(i);
    hash |= 0;
  }
  return hash.toString();
}

// 4. Check if threat was already logged recently (within last hour)
async function wasRecentlyLogged(url, type) {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const hash = createHash(`${url}_${type}`);
    
    const q = query(
      collection(db, "threat_logs"),
      where("website_url", "==", url),
      where("threat_type", "==", type),
      where("detected_at", ">", oneHourAgo)
    );
    
    const querySnapshot = await getDocs(q);
    return !querySnapshot.empty;
  } catch (e) {
    console.error("Error checking recent logs:", e);
    return false; // If error occurs, allow logging
  }
}

// 5. Export the logging function with deduplication
export async function logThreat(url, type) {
  try {
    // Check if this threat was already logged in the last hour
    const alreadyLogged = await wasRecentlyLogged(url, type);
    if (alreadyLogged) {
      console.log("Threat already logged recently, skipping duplicate...");
      return;
    }
    
    await addDoc(collection(db, "threat_logs"), {
      website_url: url,
      threat_type: type,
      detected_at: serverTimestamp(), // This adds a real-time clock stamp
      hash: createHash(`${url}_${type}`) // Store hash for reference
    });
    console.log("New threat logged to Firebase!");
  } catch (e) {
    console.error("Firebase Error: ", e);
  }
}