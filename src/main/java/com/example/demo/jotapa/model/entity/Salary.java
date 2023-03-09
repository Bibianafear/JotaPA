package com.example.demo.jotapa.model.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;



@Entity
@Table (name = "Salary")
public class Salary implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3L;
	@Id
	@GeneratedValue(strategy= GenerationType.AUTO)

	@Column (name="salary_id")
	private Long id;
	@Column
	private String company;
	@Column
	private String level;
	@Column 
	private int bonus;
	@Column 
	private int startingSalary;
	@Column 
	private int currentSalary;
	@Column 
	private boolean activeFlag;
	@Column
	private String title;
	
	
	public Salary() {
		
	}

}
