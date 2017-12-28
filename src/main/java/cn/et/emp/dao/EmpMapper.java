package cn.et.emp.dao;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.DeleteProvider;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.InsertProvider;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.Update;
import org.apache.ibatis.annotations.UpdateProvider;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.type.JdbcType;

import cn.et.emp.entity.Emp;
import cn.et.emp.entity.EmpExample;

public interface EmpMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @SelectProvider(type=EmpSqlProvider.class, method="countByExample")
    long countByExample(EmpExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @DeleteProvider(type=EmpSqlProvider.class, method="deleteByExample")
    int deleteByExample(EmpExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @Delete({
        "delete from emp",
        "where id = #{id,jdbcType=INTEGER}"
    })
    int deleteByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @Insert({
        "insert into emp (id, ename, ",
        "sal, deptid)",
        "values (#{id,jdbcType=INTEGER}, #{ename,jdbcType=VARCHAR}, ",
        "#{sal,jdbcType=DECIMAL}, #{deptid,jdbcType=INTEGER})"
    })
    int insert(Emp record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @InsertProvider(type=EmpSqlProvider.class, method="insertSelective")
    int insertSelective(Emp record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @SelectProvider(type=EmpSqlProvider.class, method="selectByExample")
    @Results({
        @Result(column="id", property="id", jdbcType=JdbcType.INTEGER, id=true),
        @Result(column="ename", property="ename", jdbcType=JdbcType.VARCHAR),
        @Result(column="sal", property="sal", jdbcType=JdbcType.DECIMAL),
        @Result(column="deptid", property="deptid", jdbcType=JdbcType.INTEGER)
    })
    List<Emp> selectByExampleWithRowbounds(EmpExample example, RowBounds rowBounds);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @SelectProvider(type=EmpSqlProvider.class, method="selectByExample")
    @Results({
        @Result(column="id", property="id", jdbcType=JdbcType.INTEGER, id=true),
        @Result(column="ename", property="ename", jdbcType=JdbcType.VARCHAR),
        @Result(column="sal", property="sal", jdbcType=JdbcType.DECIMAL),
        @Result(column="deptid", property="deptid", jdbcType=JdbcType.INTEGER)
    })
    List<Emp> selectByExample(EmpExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @Select({
        "select",
        "id, ename, sal, deptid",
        "from emp",
        "where id = #{id,jdbcType=INTEGER}"
    })
    @Results({
        @Result(column="id", property="id", jdbcType=JdbcType.INTEGER, id=true),
        @Result(column="ename", property="ename", jdbcType=JdbcType.VARCHAR),
        @Result(column="sal", property="sal", jdbcType=JdbcType.DECIMAL),
        @Result(column="deptid", property="deptid", jdbcType=JdbcType.INTEGER)
    })
    Emp selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @UpdateProvider(type=EmpSqlProvider.class, method="updateByExampleSelective")
    int updateByExampleSelective(@Param("record") Emp record, @Param("example") EmpExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @UpdateProvider(type=EmpSqlProvider.class, method="updateByExample")
    int updateByExample(@Param("record") Emp record, @Param("example") EmpExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @UpdateProvider(type=EmpSqlProvider.class, method="updateByPrimaryKeySelective")
    int updateByPrimaryKeySelective(Emp record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table emp
     *
     * @mbg.generated Wed Dec 13 09:46:59 CST 2017
     */
    @Update({
        "update emp",
        "set ename = #{ename,jdbcType=VARCHAR},",
          "sal = #{sal,jdbcType=DECIMAL},",
          "deptid = #{deptid,jdbcType=INTEGER}",
        "where id = #{id,jdbcType=INTEGER}"
    })
    int updateByPrimaryKey(Emp record);
}