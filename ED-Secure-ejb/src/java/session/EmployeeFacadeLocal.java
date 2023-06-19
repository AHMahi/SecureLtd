/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package session;

import java.util.List;
import javax.ejb.Local;
import entity.Employee;


@Local
public interface EmployeeFacadeLocal {

    Employee find(String id);

    boolean hasEmployee(String empId);
    
    boolean addEmployee(Employee employee);
    
    boolean updateEmployeeDetails(Employee employee);
    
    boolean updatePassword(String empId, String password);

    boolean deleteEmployee(String empId);
    
    boolean removeEmployee(String empId);

}
