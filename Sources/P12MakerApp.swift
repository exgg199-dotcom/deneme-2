import SwiftUI

@main
struct P12MakerApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                ContentView()
                    .tabItem {
                        Label("PKCS12", systemImage: "lock.doc")
                    }
                CSRView()
                    .tabItem {
                        Label("Signing Request", systemImage: "doc.badge.plus")
                    }
                ProfileView()
                    .tabItem {
                        Label("Profile", systemImage: "checkmark.seal")
                    }
            }
        }
    }
}
