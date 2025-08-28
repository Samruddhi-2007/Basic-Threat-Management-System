#include <iostream>
#include <string>
using namespace std;

// Node for Threat Report
class Threat_report {
public:
    int id, severity;
    string source, type, timestamp;
    Threat_report* next;
    Threat_report* prev;

    Threat_report(int i, string s, string t, int sev, string ts) {
        id = i; source = s; type = t; severity = sev; timestamp = ts;
        next = prev = NULL;
    }
};

// Doubly Linked List to store threats
class ThreatList {
private:
    Threat_report* head;

public:
    ThreatList() {
        head = NULL;
    }

    bool idExists(int id) {
        Threat_report* temp = head;
        while (temp != NULL) {
            if (temp->id == id) return true;
            temp = temp->next;
        }
        return false;
    }

    void reportThreat(int id, string source, string type, int severity, string timestamp) {
        if (idExists(id)) {
            cout << "Duplicate ID not allowed.\n";
            return;
        }
        Threat_report* nn = new Threat_report(id, source, type, severity, timestamp);
        if (head == NULL) {
            head = nn;
        } else {
            Threat_report* temp = head;
            while (temp->next != NULL) temp = temp->next;
            temp->next = nn;
            nn->prev = temp;
        }
        cout << "Threat reported successfully!\n";
    }

    void showAll() {
        if (head == NULL) {
            cout << "No threats reported.\n";
            return;
        }
        Threat_report* temp = head;
        while (temp != NULL) {
            cout << "ID: " << temp->id << ", Type: " << temp->type
                 << ", Severity: " << temp->severity << ", Source: " << temp->source
                 << ", Time: " << temp->timestamp << endl;
            temp = temp->next;
        }
    }

    void delete_byID(int id) {
        Threat_report* temp = head;
        while (temp != NULL) {
            if (temp->id == id) {
                if (temp->prev != NULL) temp->prev->next = temp->next;
                else head = temp->next;
                if (temp->next != NULL) temp->next->prev = temp->prev;
                delete temp;
                cout << "Threat ID " << id << " resolved and deleted successfully!\n";
                return;
            }
            temp = temp->next;
        }
        cout << "Threat ID not found.\n";
    }

    void searchByID(int id) {
        Threat_report* temp = head;
        while (temp != NULL) {
            if (temp->id == id) {
                cout << "Found → ID: " << temp->id << ", Type: " << temp->type
                     << ", Severity: " << temp->severity << ", Source: " << temp->source
                     << ", Time: " << temp->timestamp << endl;
                return;
            }
            temp = temp->next;
        }
        cout << "ID not found!\n";
    }

    void searchBySeverity(int sev) {
        Threat_report* temp = head;
        bool found = false;
        while (temp != NULL) {
            if (temp->severity == sev) {
                cout << "ID: " << temp->id << ", Type: " << temp->type
                     << ", Source: " << temp->source << ", Time: " << temp->timestamp << endl;
                found = true;
            }
            temp = temp->next;
        }
        if (!found) cout << "No threats with severity " << sev << ".\n";
    }

    void showMaxSeverity() {
        if (head == NULL) {
            cout << "No threats.\n";
            return;
        }
        int maxSev = head->severity;
        Threat_report* temp = head->next;
        while (temp != NULL) {
            if (temp->severity > maxSev) maxSev = temp->severity;
            temp = temp->next;
        }
        cout << "Highest Severity = " << maxSev << " Threat(s):\n";
        temp = head;
        while (temp != NULL) {
            if (temp->severity == maxSev) {
                cout << "ID: " << temp->id << ", Type: " << temp->type
                     << ", Source: " << temp->source << ", Time: " << temp->timestamp << endl;
            }
            temp = temp->next;
        }
    }

    void countThreats() {
        int count = 0;
        Threat_report* temp = head;
        while (temp != NULL) {
            count++;
            temp = temp->next;
        }
        cout << "Total active threats: " << count << endl;
    }

    void clearAll() {
        while (head != NULL) {
            Threat_report* temp = head;
            head = head->next;
            delete temp;
        }
        cout << "All threats cleared!\n";
    }

    ~ThreatList() {
        clearAll();
    }
};

int main() {
    ThreatList list;
    int choice, id, severity;
    string source, type, timestamp;

    cout << "\n=== Campus Threat Management System ===\n";
    cout << "1. Report New Threat\n";
    cout << "2. Show All Threats\n";
    cout << "3. Delete Threat by ID (Resolved)\n";
    cout << "4. Search by ID\n";
    cout << "5. Search by Severity\n";
    cout << "6. Show Highest Severity Threat(s)\n";
    cout << "7. Count Active Threats\n";
    cout << "8. Clear All (End of Day)\n";
    cout << "9. Exit\n";

    do {
        cout << "Enter choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                cout << "Enter ID: ";
                cin >> id;
                cout << "Enter Source (Firewall/Student/Antivirus): ";
                cin >> source;
                cout << "Enter Type (Malware/Phishing/DDoS/etc.): ";
                cin >> type;
                cout << "Enter Severity (1-10): ";
                cin >> severity;
                cout << "Enter Timestamp (YYYY-MM-DD_HH:MM): ";
                cin >> timestamp;
                list.reportThreat(id, source, type, severity, timestamp);
                break;
            case 2:
                list.showAll();
                break;
            case 3:
                cout << "Enter ID to delete: ";
                cin >> id;
                list.delete_byID(id);
                break;
            case 4:
                cout << "Enter ID to search: ";
                cin >> id;
                list.searchByID(id);
                break;
            case 5:
                cout << "Enter severity to search: ";
                cin >> severity;
                list.searchBySeverity(severity);
                break;
            case 6:
                list.showMaxSeverity();
                break;
            case 7:
                list.countThreats();
                break;
            case 8:
                list.clearAll();
                break;
            case 9:
                cout << "Exiting...\n";
                break;
            default:
                cout << "Invalid choice.\n";
        }
    } while (choice != 9);

    return 0;
}