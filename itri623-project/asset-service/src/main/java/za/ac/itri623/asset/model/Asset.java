package za.ac.itri623.asset.model;

import jakarta.persistence.*;

@Entity
@Table(name = "asset")
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String type; // e.g. SERVER, LAPTOP, PRINTER

    @Column(nullable = false)
    private String department;

    @Column(nullable = false)
    private String status; // e.g. ACTIVE, DECOMMISSIONED

    public Asset() {}

    public Asset(String name, String type, String department, String status) {
        this.name = name;
        this.type = type;
        this.department = department;
        this.status = status;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
