if ("serviceWorker" in navigator && "PushManager" in window) {
  navigator.serviceWorker.register("/service-worker.js").then(swReg => {
    console.log("✅ Service Worker Registered:", swReg);

    // Ask for permission
    Notification.requestPermission().then(permission => {
      if (permission === "granted") {
        console.log("🔔 Notification permission granted.");

        swReg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: "<YOUR_PUBLIC_KEY_BASE64>"
        }).then(subscription => {
          console.log("📬 Subscribed:", subscription);
          // Send the subscription to the server
          fetch("/subscribe", {
            method: "POST",
            body: JSON.stringify(subscription),
            headers: { "Content-Type": "application/json" }
          });
        }).catch(error => {
          console.error("❌ Subscription failed:", error);
        });
      } else {
        console.warn("🚫 Notification permission denied.");
      }
    });
  }).catch(error => {
    console.error("❌ Service Worker registration failed:", error);
  });
}
