/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package entity;

import java.io.Serializable;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlRootElement;


@Entity
@Table(name = "EMS_EMPLOYEE", catalog = "", schema = "APP")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "Employee.findAll", query = "SELECT e FROM Employee e"),
    @NamedQuery(name = "Employee.findByEmpid", query = "SELECT e FROM Employee e WHERE e.empid = :empid"),
    @NamedQuery(name = "Employee.findByName", query = "SELECT e FROM Employee e WHERE e.name = :name"),
    @NamedQuery(name = "Employee.findByPhone", query = "SELECT e FROM Employee e WHERE e.phone = :phone"),
    @NamedQuery(name = "Employee.findByAddress", query = "SELECT e FROM Employee e WHERE e.address = :address"),
    @NamedQuery(name = "Employee.findByEmail", query = "SELECT e FROM Employee e WHERE e.email = :email"),   
    @NamedQuery(name = "Employee.findByPassword", query = "SELECT e FROM Employee e WHERE e.password = :password"),
    @NamedQuery(name = "Employee.findByAppGroup", query = "SELECT e FROM Employee e WHERE e.appGroup = :appGroup"),   
    @NamedQuery(name = "Employee.findByBnkAccId", query = "SELECT e FROM Employee e WHERE e.bnkAccId = :bnkAccId"),
    @NamedQuery(name = "Employee.findBySalary", query = "SELECT e FROM Employee e WHERE e.salary = :salary"),
    @NamedQuery(name = "Employee.findByActive", query = "SELECT e FROM Employee e WHERE e.active = :active")})
public class Employee implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @Basic(optional = false)
    @Column(name = "EMPID")
    private String empid;
    @Column(name = "NAME")
    private String name;
    @Column(name = "PHONE")
    private String phone;
    @Column(name = "ADDRESS")
    private String address;
    @Column(name = "EMAIL")
    private String email;
    @Column(name = "PASSWORD")
    private String password;
    @Column(name = "APPGROUP")
    private String appGroup;
    @Column(name = "BANKACCOUNTID")
    private String bnkAccId;
    // @Max(value=?)  @Min(value=?)//if you know range of your decimal fields consider using these annotations to enforce field validation
    @Column(name = "SALARY")
    private Double salary;
    @Column(name = "ACTIVE")
    private Boolean active;

    public Employee() {
    }

    public Employee(String empid) {
        this.empid = empid;
    }

    public Employee(String empid, String name, String phone, String address, String email, String password, String appGroup, String bnkAccId, Double salary, Boolean active) {
        this.empid = empid;
        this.name = name;
        this.phone = phone;
        this.address = address;
        this.email = email;
        this.password = password;
        this.appGroup = appGroup;
        this.bnkAccId = bnkAccId;
        this.salary = salary;
        this.active = active;
    }
    
    public String getEmpid() {
        return empid;
    }

    public void setEmpid(String empid) {
        this.empid = empid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
    
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAppGroup() {
        return appGroup;
    }

    public void setAppGroup(String appGroup) {
        this.appGroup = appGroup;
    }
    
    public String getBnkAccId() {
        return bnkAccId;
    }

    public void setBnkAccId(String bnkAccId) {
        this.bnkAccId = bnkAccId;
    }

    public Double getSalary() {
        return salary;
    }

    public void setSalary(Double salary) {
        this.salary = salary;
    }

    public Boolean isActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (empid != null ? empid.hashCode() : 0);
        return hash;
    }


    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Employee)) {
            return false;
        }
        Employee other = (Employee) object;
        if ((this.empid == null && other.empid != null) || (this.empid != null && !this.empid.equals(other.empid))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "persistence.entity.Employee[ empid=" + empid + " ]";
    }
 
    public boolean checkPassword(String password) {
        return this.password.equals(password);
    }
}
