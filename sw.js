// Service Worker for background push notifications
self.addEventListener("push", function (event) {
  let data = {
    title: "New Delivery Request!",
    body: "A new live delivery request is available in your area.",
    url: "/delivery.html"
  };

  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data.body = event.data.text();
    }
  }

  const options = {
    body: data.body,
    vibrate: [200, 100, 200],
    data: {
      url: data.url
    }
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  
  event.waitUntil(
    clients.openWindow(event.notification.data.url || "/delivery.html")
  );
});

