/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package web;

import java.io.Serializable;
import javax.ejb.EJB;
import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.FacesContext;
import javax.faces.validator.ValidatorException;
import javax.inject.Inject;
import javax.inject.Named;
import session.EmployeeManagementRemote;
import entity.EmployeeDTO;


@Named(value = "myEmpManagedBean")
@ConversationScoped
public class MyEmpManagedBean implements Serializable {

    @Inject
    private Conversation conversation;
    @EJB
    private EmployeeManagementRemote employeeManagement;

    private String empId;
    private String name;
    private String phone;
    private String address;
    private String email;
    private String password;
    private String newPassword;
    private String confirmPassword;
    private String appGroup;
    private String bnkAccId;
    private Double salary;
    private Boolean active;

    /**
     * Creates a new instance of MyEmpManagedBean
     */
    public MyEmpManagedBean() {
        empId = null;
        name = null;
        phone = null;
        address = null;
        email = null;
        password = null;
        newPassword = null;
        confirmPassword = null;
        appGroup = null;
        bnkAccId = null;
        salary = 0.0;
        active = false;
    }

    public String getEmpId() {
        return empId;
    }

    public void setEmpId(String empId) {
        this.empId = empId;
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

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
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

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public boolean validSalary() {
        boolean b = (salary > 0.0);
//        return (salary > 0.0);
        return b;
    }

    public void startConversation() {
        conversation.begin();
    }

    public void endConversation() {
        conversation.end();
    }

    public String addEmployee() {

        // check empId is null
        if (isNull(empId)) {
            return "debug";
        }

        // all information seems to be valid
        // try add the employee
        EmployeeDTO empDTO = new EmployeeDTO(empId, name, phone,
                address, email, password, appGroup, bnkAccId, salary, active);
        boolean result = employeeManagement.addEmployee(empDTO);
        if (result) {
            return "success";
        } else {
            return "failure";
        }
    }

    public String setEmployeeDetailsForChange() {
        // check empId is null
        if (isNull(empId) || conversation == null) {
            return "debug";
        }

        if (!employeeManagement.hasEmployee(empId)) {
            return "failure";
        }

        // note the startConversation of the conversation
        startConversation();

        // get employee details
        return setEmployeeDetails();
    }

    public String changeEmployee() {
        // check empId is null
        if (isNull(empId)) {
            return "debug";
        }

        EmployeeDTO empDTO = new EmployeeDTO(empId, name, phone,
                address, email, password, appGroup, bnkAccId, salary, active);
        boolean result = employeeManagement.updateEmpolyeeDetails(empDTO);

        // note the endConversation of the conversation
        endConversation();

        if (result) {
            return "success";
        } else {
            return "failure";
        }
    }

    public void validateNewPassword(FacesContext context,
            UIComponent componentToValidate, Object value)
            throws ValidatorException {

        // get new password
        String oldPwd = (String) value;

        // get old password
        UIInput newPwdComponent = (UIInput) componentToValidate.getAttributes().get("newpwd");
        String newPwd = (String) newPwdComponent.getSubmittedValue();

        if (oldPwd.equals(newPwd)) {
            FacesMessage message = new FacesMessage(
                    "Old Password and New Password are the same! They must be different.");
            throw new ValidatorException(message);
        }

    }

    public void validatePasswordPair(FacesContext context,
            UIComponent componentToValidate,
            Object pwdValue) throws ValidatorException {

        // get password
        String pwd = (String) pwdValue;

        // get confirm password
        UIInput cnfPwdComponent = (UIInput) componentToValidate.getAttributes().get("cnfpwd");
        String cnfPwd = (String) cnfPwdComponent.getSubmittedValue();

        System.out.println("password : " + pwd);
        System.out.println("confirm password : " + cnfPwd);

        if (!pwd.equals(cnfPwd)) {
            FacesMessage message = new FacesMessage(
                    "Password and Confirm Password are not the same! They must be the same.");
            throw new ValidatorException(message);
        }
    }

    public void validateNewPasswordPair(FacesContext context,
            UIComponent componentToValidate,
            Object newValue) throws ValidatorException {

        // get new password
        String newPwd = (String) newValue;

        // get confirm password
        UIInput cnfPwdComponent = (UIInput) componentToValidate.getAttributes().get("cnfpwd");
        String cnfPwd = (String) cnfPwdComponent.getSubmittedValue();

        System.out.println("new password : " + newPwd);
        System.out.println("confirm password : " + cnfPwd);

        if (!newPwd.equals(cnfPwd)) {
            FacesMessage message = new FacesMessage(
                    "New Password and Confirm New Password are not the same! They must be the same.");
            throw new ValidatorException(message);
        }
    }

    public String changeEmployeePassword() {
        // check empId is null
        if (isNull(empId)) {
            return "debug";
        }

        // newPassword and confirmPassword are the same - checked by the validator during input to JSF form
        boolean result = employeeManagement.updateEmployeePassword(empId, newPassword);

        System.out.println("result = " + result);

        if (result) {
            return "success";
        } else {
            return "failure";
        }
    }

    public String deleteEmployee() {
        // check empId is null
        if (isNull(empId)) {
            return "debug";
        }

        boolean result = employeeManagement.deleteEmployee(empId);

        if (result) {
            return "success";
        } else {
            return "failure";
        }

    }

    public String displayEmployee() {
        // check empId is null
        if (isNull(empId) || conversation == null) {
            return "debug";
        }

        return setEmployeeDetails();
    }

    private boolean isNull(String s) {
        return (s == null);
    }

    private String setEmployeeDetails() {

        if (isNull(empId) || conversation == null) {
            return "debug";
        }

        EmployeeDTO e = employeeManagement.getEmployeeDetails(empId);

        if (e == null) {
            // no such employee
            return "failure";
        } else {
            // found - set details for display
            this.empId = e.getEmpid();
            this.name = e.getName();
            this.phone = e.getPhone();
            this.address = e.getAddress();
            this.email = e.getEmail();
            this.password = e.getPassword();
            this.appGroup = e.getAppGroup();
            this.bnkAccId = e.getBnkAccId();
            this.salary = e.getSalary();
            this.active = e.isActive();
            return "success";
        }
    }

    private boolean validAddEmployeeInfo() {
        return (empId != null && name != null && phone != null && address != null
                && email != null && password != null && appGroup != null
                && bnkAccId != null && salary > 0.0);
    }
    
                                    //User
    
    public String displayUser() {
        // check empId is null
        if (isNull(empId) || conversation == null) {
            return "debug";
        }

        return setUserDetails();
    }
    
    public String setUserDetailsForChange() {
        // check empId is null
        if (isNull(empId) || conversation == null) {
            return "debug";
        }

        if (!employeeManagement.hasEmployee(empId)) {
            return "failure";
        }

        // note the startConversation of the conversation
        startConversation();

        // get employee details
        return setUserDetails();
    }
    
    private String setUserDetails() {

        if (isNull(empId) || conversation == null) {
            return "debug";
        }

        EmployeeDTO e = employeeManagement.getUserDetails(empId, password);

        if (e == null) {
            // no such employee
            return "failure";
        } else {
            // found - set details for display
            this.empId = e.getEmpid();
            this.name = e.getName();
            this.phone = e.getPhone();
            this.address = e.getAddress();
            this.email = e.getEmail();
            this.password = e.getPassword();
            this.appGroup = e.getAppGroup();
            this.bnkAccId = e.getBnkAccId();
            this.salary = e.getSalary();
            this.active = e.isActive();
            return "success";
        }
    }
    
    public String changeUser() {
        // check empId is null
        if (isNull(empId)) {
            return "debug";
        }

        EmployeeDTO empDTO = new EmployeeDTO(empId, name, phone,
                address, email, password, appGroup, bnkAccId, salary, active);
        boolean result = employeeManagement.updateEmpolyeeDetails(empDTO);

        // note the endConversation of the conversation
        endConversation();

        if (result) {
            return "success";
        } else {
            return "failure";
        }
    }
    
    public String changeUserPassword() {
        // check empId is null
        if (isNull(empId)) {
            return "debug";
        }

        // newPassword and confirmPassword are the same - checked by the validator during input to JSF form
        boolean result = employeeManagement.updateUserPassword(empId, password, newPassword);

        System.out.println("result = " + result);

        if (result) {
            return "success";
        } else {
            return "failure";
        }
    }

}
