# main.py
import sys
import os
import csv
import joblib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QPushButton, QProgressBar, 
                             QTableWidget, QTableWidgetItem, QFileDialog, 
                             QMessageBox, QLabel, QHeaderView)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QColor, QFont

# 导入你刚才写的特征提取引擎
from feature_engine import FeatureExtractor

class DetectionWorker(QThread):
    """
    后台工作线程：完美契合论文里写的“QThread异步防假死技术”
    避免在处理成千上万条URL时，主界面卡住无法拖动
    """
    progress_update = pyqtSignal(int, str)  # 传递进度百分比和文本
    result_ready = pyqtSignal(dict)         # 传递单条检测结果
    finished = pyqtSignal()                 # 检测完成信号

    def __init__(self, urls, model, extractor):
        super().__init__()
        self.urls = urls
        self.model = model
        self.extractor = extractor

    def run(self):
        total = len(self.urls)
        for index, url in enumerate(self.urls):
            url = url.strip()
            if not url:
                continue
                
            try:
                # 1. 提取25维静态特征 (这里对应论文的特征对齐)
                features = self.extractor.extract_features(url)
                
                # 2. 模型推断
                pred_label = self.model.predict(features)[0]
                pred_proba = self.model.predict_proba(features)[0]
                
                # 获取恶意类别的置信度 (标签1的概率)
                malicious_score = pred_proba[1] * 100
                
                result_dict = {
                    "url": url,
                    "label": int(pred_label),
                    "score": round(malicious_score, 2)
                }
                self.result_ready.emit(result_dict)
                
            except Exception as e:
                print(f"Error processing {url}: {e}")
                
            # 更新进度
            percent = int(((index + 1) / total) * 100)
            status_text = f"处理进度: {percent}% (已检测: {index + 1} / 总计: {total})"
            self.progress_update.emit(percent, status_text)
            
        self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ 基于URL特征的恶意链接检测工具 v1.0")
        self.resize(900, 650)
        
        # 这一行在执行时报错了
        self.extractor = FeatureExtractor()
        self.model = self.load_model()  # <--- 程序在这里找下面的函数
        
        self.init_ui()

    # 重点：确保这个函数在 MainWindow 类里面！
    def load_model(self):
        import os, sys, joblib
        
        # 既然要打包，建议直接用这个最稳妥的路径写法
        if getattr(sys, 'frozen', False):
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        model_path = os.path.join(base_path, "rf_model.pkl")
        
        if not os.path.exists(model_path):
            QMessageBox.critical(self, "错误", f"找不到模型文件：\n{model_path}")
            sys.exit(1)
            
        return joblib.load(model_path)

    def init_ui(self):
        """构建图形用户界面"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)

        # ====== 顶部输入区 ======
        input_layout = QHBoxLayout()
        
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("请输入需要检测的URL链接（支持粘贴多行），或点击右侧按钮导入批量文件...")
        self.text_edit.setFont(QFont("Consolas", 11))
        self.text_edit.setStyleSheet("border: 1px solid #bdc3c7; border-radius: 5px; padding: 5px;")
        
        btn_layout = QVBoxLayout()
        self.btn_import = QPushButton("📁 导入批量文件")
        self.btn_detect = QPushButton("▶ 开始安全检测")
        
        # 按钮样式美化
        self.btn_import.setStyleSheet("background-color: #34495e; color: white; padding: 10px; border-radius: 5px; font-weight: bold;")
        self.btn_detect.setStyleSheet("background-color: #27ae60; color: white; padding: 10px; border-radius: 5px; font-weight: bold; font-size: 14px;")
        
        self.btn_import.clicked.connect(self.import_file)
        self.btn_detect.clicked.connect(self.start_detection)
        
        btn_layout.addWidget(self.btn_import)
        btn_layout.addWidget(self.btn_detect)
        
        input_layout.addWidget(self.text_edit, stretch=4)
        input_layout.addLayout(btn_layout, stretch=1)
        main_layout.addLayout(input_layout, stretch=2)

        # ====== 中部进度条区 ======
        self.status_label = QLabel("系统就绪，等待输入...")
        self.status_label.setStyleSheet("color: #7f8c8d; font-weight: bold;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar { border: 1px solid #bdc3c7; border-radius: 5px; text-align: center; }
            QProgressBar::chunk { background-color: #3498db; width: 10px; }
        """)
        
        main_layout.addWidget(self.status_label)
        main_layout.addWidget(self.progress_bar)

        # ====== 底部结果表格区 ======
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["序号", "目标 URL 链接", "威胁置信度", "研判结果"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch) # URL列自适应拉伸
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 150)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("alternate-background-color: #f9f9f9; background-color: #ffffff;")
        
        main_layout.addWidget(self.table, stretch=5)

        # ====== 导出报告按钮 ======
        self.btn_export = QPushButton("💾 导出检测报告 (CSV)")
        self.btn_export.setStyleSheet("background-color: #e67e22; color: white; padding: 8px 15px; border-radius: 4px; font-weight: bold;")
        self.btn_export.clicked.connect(self.export_csv)
        
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.btn_export)
        main_layout.addLayout(bottom_layout)

    def import_file(self):
        """批量导入TXT或CSV文件"""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "选择包含URL的文件", "", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)", options=options)
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    urls = f.read()
                    self.text_edit.setText(urls)
                self.status_label.setText(f"成功导入文件: {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.warning(self, "读取失败", f"无法读取文件: {e}")

    def start_detection(self):
        """启动后台线程进行检测"""
        text = self.text_edit.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "提示", "请输入或导入需要检测的URL！")
            return
            
        urls = [line.strip() for line in text.split('\n') if line.strip()]
        
        # 清空表格并重置进度
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        
        # 禁用按钮防止重复点击
        self.btn_detect.setEnabled(False)
        self.btn_import.setEnabled(False)
        
        # 启动 QThread 工作线程
        self.worker = DetectionWorker(urls, self.model, self.extractor)
        self.worker.progress_update.connect(self.update_progress)
        self.worker.result_ready.connect(self.append_result)
        self.worker.finished.connect(self.detection_finished)
        self.worker.start()

    def update_progress(self, percent, text):
        self.progress_bar.setValue(percent)
        self.status_label.setText(text)

    def append_result(self, result):
        """将单条结果追加到UI表格中"""
        row_idx = self.table.rowCount()
        self.table.insertRow(row_idx)
        
        # 序号
        item_id = QTableWidgetItem(str(row_idx + 1))
        item_id.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row_idx, 0, item_id)
        
        # URL
        self.table.setItem(row_idx, 1, QTableWidgetItem(result['url']))
        
        # 置信度
        item_score = QTableWidgetItem(f"{result['score']} %")
        item_score.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row_idx, 2, item_score)
        
        # 研判结果及颜色高亮
        if result['label'] == 1:
            item_result = QTableWidgetItem("🚨 恶意链接")
            item_result.setForeground(QColor("#c0392b"))
            item_score.setForeground(QColor("#c0392b"))
        else:
            item_result = QTableWidgetItem("✅ 正常链接")
            item_result.setForeground(QColor("#27ae60"))
            item_score.setForeground(QColor("#27ae60"))
            
        item_result.setFont(QFont("Microsoft YaHei", 10, QFont.Bold))
        item_result.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row_idx, 3, item_result)
        
        # 自动滚动到最新一行
        self.table.scrollToBottom()

    def detection_finished(self):
        """检测完成回调"""
        self.btn_detect.setEnabled(True)
        self.btn_import.setEnabled(True)
        self.status_label.setText("✅ 检测完毕！结果已渲染完成。")
        QMessageBox.information(self, "完成", "所有URL已检测完毕！")

    def export_csv(self):
        """将表格结果导出为CSV报表"""
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "提示", "表格中没有数据可导出！")
            return
            
        path, _ = QFileDialog.getSaveFileName(self, "导出检测报告", "Detection_Report.csv", "CSV Files (*.csv)")
        if path:
            try:
                # 加上 utf-8-sig 防止Excel打开中文乱码
                with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['序号', '目标URL', '威胁置信度(%)', '研判结果'])
                    for row in range(self.table.rowCount()):
                        row_data =[
                            self.table.item(row, 0).text(),
                            self.table.item(row, 1).text(),
                            self.table.item(row, 2).text().replace(' %', ''),
                            self.table.item(row, 3).text()
                        ]
                        writer.writerow(row_data)
                QMessageBox.information(self, "成功", f"报告已成功导出至：\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败：{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # 全局字体设置
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())