/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package session;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import entity.Employee;


@Stateless
public class EmployeeFacade implements EmployeeFacadeLocal {

    @PersistenceContext(unitName = "ED-Secure-ejbPU")
    private EntityManager em;

    public EmployeeFacade() {
    }

    private void create(Employee entity) {
        em.persist(entity);
    }

    private void edit(Employee entity) {
        em.merge(entity);
    }

    private void remove(Employee entity) {
        em.remove(em.merge(entity));
    }

    /**
     *
     * @param id
     * @return
     */
    @Override
    public Employee find(String id) {
        return em.find(Employee.class, id);
    }

    /**
     * checks whether an employee exist using empId
     *
     * @param empId
     * @return true if exist, false otherwise
     */
    @Override
    public boolean hasEmployee(String empId) {
        return (find(empId) != null);
    }

    /**
     * add an employee to the system
     *
     * @param employee
     * @return true if addition is successful, false otherwise
     */
    @Override
    public boolean addEmployee(Employee employee) {
        // check again - just to play it safe
        Employee e = find(employee.getEmpid());
        
        if (e != null) {
            // could not add one
            return false;
        }

        create(employee);

        return true;
    }

    /**
     * update employee details without changing password
     *
     * @param employee
     * @return true if update is successful, false otherwise
     */
    @Override
    public boolean updateEmployeeDetails(Employee employee) {
        // find the employee, just in case
        Employee e = find(employee.getEmpid());

        // check again - just to play it safe
        if (e == null) {
            return false;
        }

        // no need to update the primary key - empId
        edit(employee);
        return true;
    }

    /**
     * update employee's password
     *
     * @param empId
     * @param password
     * @return true if update is successful, false otherwise
     */
    @Override
    public boolean updatePassword(String empId, String password) {
        // find the employee
        Employee e = find(empId);

        // check again - just to play it safe
        if (e == null) {
            return false;
        }

        // only need to update the password field
        e.setPassword(password);
        return true;
    }

    /**
     * delete the employee by setting active to false - cannot physically
     * removing the record due to taxation purposes
     *
     * @param empId
     * @return true if successful, false otherwise
     */
    @Override
    public boolean deleteEmployee(String empId) {
        // find the employee
        Employee e = find(empId);

        // check again - just to play it safe
        if (e == null) {
            return false;
        }

        if (!e.isActive()) {
            // employee not active already
            return false;
        }

        e.setActive(false);
        return true;
    }

    /**
     * physically remove the employee record from database table
     * 
     * this is only for lab purposes - never ever do this in real world applications
     *
     * @param empId
     * @return true if successful, false otherwise
     */
    @Override
    public boolean removeEmployee(String empId) {
        // find the employee
        Employee e = find(empId);

        // check again - just to play it safe
        if (e == null) {
            return false;
        }

        em.remove(e);
        return true;
    }
}
